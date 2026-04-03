package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, statusCode int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeAndValidateMediaMessage(mediaType, filePayload string) ([]byte, error) {
	data, err := DecodeBase64File(filePayload)
	if err != nil {
		return nil, err
	}
	if err := ValidateUploadPayload(mediaType, data); err != nil {
		return nil, err
	}

	return data, nil
}

func executeSendMsg(m *SendMsg) error {
	if m.ResultCh == nil {
		m.ResultCh = make(chan error, 1)
	}

	msgChan <- m

	select {
	case err := <-m.ResultCh:
		return err
	case <-time.After(requestWaitTimeout):
		return fmt.Errorf("request timeout waiting for %s", m.Type)
	}
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"status":  "failed",
			"message": "仅支持 POST",
		})
		Error("仅支持 POST")
		return
	}

	req := new(SendRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status":  "failed",
			"message": "无效的 JSON",
		})
		Error("无效的 JSON")
		return
	}

	// 参数校验
	if len(req.Message) == 0 || (req.UserID == "" && req.GroupID == "") {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status":  "failed",
			"message": "参数缺失",
		})
		Error("参数缺失")
		return
	}

	sendContent := ""
	atUserID := ""
	for _, v := range req.Message {
		if v.Type == "text" {
			sendContent += v.Data.Text
		} else if v.Type == "at" {
			if req.GroupID != "" {
				if nicknameInter, ok := userID2NicknameMap.Load(req.GroupID + "_" + v.Data.QQ); ok {
					sendContent += fmt.Sprintf("@%s\u2005", nicknameInter.(string))
					atUserID += v.Data.QQ + ","
				}
			}

		} else if v.Type == "image" || v.Type == "video" {
			fileData, err := decodeAndValidateMediaMessage(v.Type, v.Data.File)
			if err != nil {
				statusCode := http.StatusBadRequest
				if v.Type == "image" && strings.Contains(err.Error(), "too large") {
					statusCode = http.StatusRequestEntityTooLarge
				}
				writeJSON(w, statusCode, map[string]any{
					"status":  "failed",
					"message": err.Error(),
				})
				Error("媒体消息校验失败", "type", v.Type, "err", err)
				return
			}
			if err := executeSendMsg(&SendMsg{
				UserId:   req.UserID,
				GroupID:  req.GroupID,
				Type:     v.Type,
				FileData: fileData,
			}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"status":  "failed",
					"message": err.Error(),
				})
				Error("媒体消息发送失败", "type", v.Type, "err", err)
				return
			}
		}
	}

	if sendContent != "" {
		if err := executeSendMsg(&SendMsg{
			UserId:  req.UserID,
			GroupID: req.GroupID,
			Content: sendContent,
			Type:    "text",
			AtUser:  strings.TrimRight(atUserID, ","),
		}); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"status":  "failed",
				"message": err.Error(),
			})
			Error("文本消息发送失败", "err", err)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": "sent",
	})
}

func SendHttpReq(jsonData []byte) {
	defer func() {
		if r := recover(); r != nil {
			Error("http panic", "err", r, "stack", string(debug.Stack()))
		}
	}()

	time.Sleep(time.Duration(config.SendInterval) * time.Millisecond)
	jsonReq, err := HandleMsg(jsonData)
	if err != nil {
		Error("JSON 序列化失败", "err", err)
		return
	}
	if jsonReq == nil {
		return
	}

	Info("发送数据", "msg", string(jsonReq))
	req, err := http.NewRequest("POST", config.SendURL, bytes.NewBuffer(jsonReq))
	if err != nil {
		Error("创建请求失败", "err", err)
		return
	}

	// 5. 设置 Header (OneBot 接口通常要求 application/json)
	h := hmac.New(sha1.New, []byte(config.OnebotToken))
	h.Write(jsonReq)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", "sha1="+hex.EncodeToString(h.Sum(nil)))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	// 6. 执行请求
	resp, err := client.Do(req)
	if err != nil {
		Error("请求执行失败", "err", err)
		return
	}
	defer resp.Body.Close()

	// 7. 读取返回结果
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Error("读取响应失败", "err", err)
		return
	}

	Info("返回内容", "status", resp.StatusCode, "body", string(body))
}
