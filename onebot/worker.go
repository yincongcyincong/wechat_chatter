package main

import (
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

const (
	sendStageTimeout   = 15 * time.Second
	uploadStageTimeout = 30 * time.Second
	requestWaitTimeout = 45 * time.Second
)

func SendWorker() {
	defer func() {
		if err := recover(); err != nil {
			Error("SendWorker panic", "err", err, "stack", string(debug.Stack()))
			go SendWorker()
		}
	}()

	for {
		m, ok := <-msgChan
		if !ok {
			Fatal("发送通道关闭")
			return
		}

		err := SendWechatMsg(m)
		if m.ResultCh != nil {
			m.ResultCh <- err
		}
	}
}

func registerPendingResult(m *sync.Map, key string) chan error {
	ch := make(chan error, 1)
	m.Store(key, ch)
	return ch
}

func waitPendingResult(m *sync.Map, key string, ch chan error, timeout time.Duration, stage string) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		m.Delete(key)
		return fmt.Errorf("%s timeout", stage)
	}
}

func resolvePendingResult(m *sync.Map, key string, err error) {
	if chInter, ok := m.LoadAndDelete(key); ok {
		ch := chInter.(chan error)
		ch <- err
	}
}

func nextTaskID() int64 {
	return atomic.AddInt64(&taskId, 1)
}

func nextRequestID() string {
	return fmt.Sprintf("upload-%d-%d", time.Now().UnixNano(), atomic.AddInt64(&requestSeq, 1))
}

func taskKey(taskID int64) string {
	return fmt.Sprintf("%d", taskID)
}

func runSendTask(taskID int64, targetID, stage string, call func() any) error {
	key := taskKey(taskID)
	ch := registerPendingResult(&pendingTaskMap, key)

	result := fmt.Sprint(call())
	Info("📩 发送任务执行结果", "stage", stage, "result", result, "task_id", taskID, "target_id", targetID)
	if result != "1" {
		pendingTaskMap.Delete(key)
		return fmt.Errorf("%s failed: result=%s", stage, result)
	}

	return waitPendingResult(&pendingTaskMap, key, ch, sendStageTimeout, stage)
}

func runUploadTask(requestID, stage string, call func() any) error {
	ch := registerPendingResult(&pendingUploadMap, requestID)

	result := fmt.Sprint(call())
	Info("📩 上传任务执行结果", "stage", stage, "result", result, "request_id", requestID)
	if result != "0" {
		pendingUploadMap.Delete(requestID)
		return fmt.Errorf("%s failed: result=%s", stage, result)
	}

	return waitPendingResult(&pendingUploadMap, requestID, ch, uploadStageTimeout, stage)
}

func SendWechatMsg(m *SendMsg) error {
	time.Sleep(time.Duration(config.SendInterval) * time.Millisecond)
	Info("📩 收到任务", "type", m.Type, "request_id", m.RequestID)

	targetId := m.UserId
	if m.GroupID != "" {
		targetId = m.GroupID
	}

	if targetId == "" {
		return errors.New("target is empty")
	}

	switch m.Type {
	case "text":
		currTaskID := nextTaskID()
		return runSendTask(currTaskID, targetId, "send_text", func() any {
			return fridaScript.ExportsCall("triggerSendTextMessage", currTaskID, targetId, m.Content, m.AtUser)
		})
	case "image":
		targetPath, md5Str, err := SaveImageData(m.FileData)
		if err != nil {
			return fmt.Errorf("save image failed: %w", err)
		}
		requestID := m.RequestID
		if requestID == "" {
			requestID = nextRequestID()
		}
		if err := runUploadTask(requestID, "upload_image", func() any {
			return fridaScript.ExportsCall("triggerUploadImg", requestID, targetId, md5Str, targetPath)
		}); err != nil {
			return err
		}
		currTaskID := nextTaskID()
		return runSendTask(currTaskID, targetId, "send_image", func() any {
			return fridaScript.ExportsCall("triggerSendImgMessage", currTaskID, myWechatId, targetId)
		})
	case "video":
		targetPath, md5Str, err := SaveImageData(m.FileData)
		if err != nil {
			return fmt.Errorf("save video failed: %w", err)
		}
		requestID := m.RequestID
		if requestID == "" {
			requestID = nextRequestID()
		}
		if err := runUploadTask(requestID, "upload_video", func() any {
			return fridaScript.ExportsCall("triggerUploadVideo", requestID, targetId, md5Str, targetPath)
		}); err != nil {
			return err
		}
		currTaskID := nextTaskID()
		return runSendTask(currTaskID, targetId, "send_video", func() any {
			return fridaScript.ExportsCall("triggerSendVideoMessage", currTaskID, myWechatId, targetId)
		})
	case "download":
		result := fridaScript.ExportsCall("triggerDownload", targetId, m.FIleCdnUrl, m.AesKey, m.FilePath, m.FileType)
		Info("📩 下载任务执行结果", "result", result, "wechat_id", myWechatId, "target_id", targetId)
		return nil
	default:
		return fmt.Errorf("unsupported message type: %s", m.Type)
	}

	return nil
}

func HandleMsg(jsonData []byte) ([]byte, error) {
	m := new(WechatMessage)
	err := json.Unmarshal(jsonData, m)
	if err != nil {
		Error("解析消息失败", "err", err)
		return nil, err
	}
	myWechatId = m.SelfID
	if m.GroupId != "" {
		userID2NicknameMap.Store(m.GroupId+"_"+m.UserID, m.Sender.Nickname)
	}

	for _, msg := range m.Message {
		switch msg.Type {
		case "record":
			path, err := SaveAudioFile(msg.Data.Media)
			if err != nil {
				Error("保存音频失败", "err", err)
				return nil, err
			}
			msg.Data.URL = "file://" + path
			msg.Data.Media = nil
		case "image":
			var fileMsg FileMsg
			err = xml.Unmarshal([]byte(msg.Data.Text), &fileMsg)
			if err != nil {
				Error("XML解析失败", "err", err)
				return nil, err
			}

			path, err := GetDownloadPath(fileMsg.Image.MidImgURL, fileMsg.Image.AesKey)
			if err != nil {
				Error("获取文件路径失败", "err", err)
				return nil, err
			}

			msg.Data.URL = "file://" + path

		case "file":
			var fileMsg FileMsg
			err = xml.Unmarshal([]byte(msg.Data.Text), &fileMsg)
			if err != nil {
				Error("XML解析失败", "err", err)
				return nil, err
			}
			path, err := GetDownloadPath(fileMsg.AppMsg.AppAttach.CdnAttachURL, fileMsg.AppMsg.AppAttach.AesKey)
			if err != nil {
				Error("获取文件路径失败", "err", err)
				return nil, err
			}

			msg.Data.URL = "file://" + path
		case "video":
			var fileMsg FileMsg
			err = xml.Unmarshal([]byte(msg.Data.Text), &fileMsg)
			if err != nil {
				Error("XML解析失败", "err", err)
				return nil, err
			}
			path, err := GetDownloadPath(fileMsg.Video.CdnVideoUrl, fileMsg.Video.AesKey)
			if err != nil {
				Error("获取文件路径失败", "err", err)
				return nil, err
			}

			msg.Data.URL = "file://" + path
		case "face":
			var fileMsg FileMsg
			err = xml.Unmarshal([]byte(msg.Data.Text), &fileMsg)
			if err != nil {
				Error("XML解析失败", "err", err)
				return nil, err
			}

			data, err := DownloadFile(fileMsg.Emoji.ThumbUrl)
			if err != nil {
				Error("下载表情失败", "err", err)
				return nil, err
			}

			path, err := DetectAndSaveImage(data)
			if err != nil {
				Error("保存表情失败", "err", err)
				return nil, err
			}

			msg.Data.URL = "file://" + path
		}
	}
	return json.Marshal(m)
}

func GetDownloadPath(cdnUrl, aesKeyStr string) (string, error) {
	for i := 0; i < 10; i++ {
		if downloadMsgInter, ok := userID2FileMsgMap.Load(cdnUrl); ok {
			downloadReq := downloadMsgInter.(*DownloadRequest)
			if downloadReq.FilePath != "" {
				return downloadReq.FilePath, nil
			}

			// 检查数据是否还在接收中
			timeSinceLastAppend := time.Now().UnixMilli() - downloadReq.LastAppendTime
			Info("文件等待下载", "url", cdnUrl, "times", i, "last_append_time", timeSinceLastAppend)

			// 如果数据仍在接收中（1秒内有新数据），继续等待
			if timeSinceLastAppend < 1000 && i < 9 {
				time.Sleep(2 * time.Second)
				continue
			}

			// 数据接收完成，尝试解密
			if len(downloadReq.Media) > 0 {
				aesKey, err := hex.DecodeString(aesKeyStr)
				if err != nil {
					Error("AES key 解码失败", "err", err)
					return "", err
				}
				filePath, err := GetFilePath(downloadReq.Media, aesKey)
				if err != nil {
					Error("获取文件路径失败", "err", err, "media_len", len(downloadReq.Media))
					userID2FileMsgMap.Delete(cdnUrl)
					return "", err
				}

				downloadReq.FilePath = filePath
				downloadReq.Media = nil
				return filePath, nil
			}
		}

		time.Sleep(2 * time.Second)
	}

	return "", errors.New("文件下载超时或数据为空")
}
