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
	"net/url"
	"runtime/debug"
	"strings"
	"time"
)

func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		Error("仅支持 POST")
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if config.OnebotToken == "" || token == "" || !hmac.Equal([]byte(token), []byte(config.OnebotToken)) {
		http.Error(w, "未授权", http.StatusUnauthorized)
		Error("未授权")
		return
	}

	req := new(SendRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "无效的 JSON", http.StatusBadRequest)
		Error("无效的 JSON")
		return
	}

	// 参数校验
	if len(req.Message) == 0 || (req.UserID == "" && req.GroupID == "") {
		http.Error(w, "参数缺失", http.StatusBadRequest)
		Error("参数缺失")
		return
	}

	sendContent := ""
	atUserID := ""
	var resultChans []chan error
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

		} else if v.Type == "image" || v.Type == "video" || v.Type == "record" || v.Type == "voice" || v.Type == "file" {
			msgType := v.Type
			if msgType == "record" || msgType == "voice" {
				msgType = "voice"
			}
			// file: 走 iPad860 风格 uploadappattach 直传(不走 CDN)
			if msgType == "file" {
				msgType = "send_file_simple"
			}
			ch := make(chan error, 1)
			msg := &SendMsg{
				UserId:     req.UserID,
				GroupID:    req.GroupID,
				Content:    v.Data.File,
				Type:       msgType,
				ResultChan: ch,
			}
			msgChan <- msg
			resultChans = append(resultChans, ch)
		} else if v.Type == "reply" {
			if v.Data.ReplyMessage == nil {
				Error("reply_message为空")
				continue
			}
			rm := v.Data.ReplyMessage

			// 顶层没有group_id时，从reply_message中取
			if req.GroupID == "" && rm.GroupId != "" {
				req.GroupID = rm.GroupId
			}

			// 提取被回复消息的内容
			referContent := ""
			referMsgType := 1 // 默认text
			if len(rm.Message) > 0 {
				switch rm.Message[0].Type {
				case "text":
					referContent = rm.Message[0].Data.Text
					referMsgType = 1
				case "image":
					referMsgType = 3
				case "video":
					referMsgType = 43
				case "file":
					referMsgType = 49
				}
			}

			// 提取发送者昵称
			displayName := ""
			if rm.Sender != nil {
				displayName = rm.Sender.Nickname
			}

			// msgsource需要JSON unescape（双重编码: \\u003c → \u003c → <）
			msgsource := jsonUnescapeString(rm.MsgResource)

			ch := make(chan error, 1)
			msgChan <- &SendMsg{
				UserId:           req.UserID,
				GroupID:          req.GroupID,
				Content:          v.Data.Text,
				Type:             "reply",
				ReferMsgId:       rm.MessageId,
				ReferMsgSender:   rm.UserID,
				ReferMsgType:     referMsgType,
				ReferCreateTime:  rm.Time,
				ReferMsgsource:   msgsource,
				ReferDisplayName: displayName,
				ReferContent:     referContent,
				ResultChan:       ch,
			}
			resultChans = append(resultChans, ch)
		}
	}

	if sendContent != "" {
		ch := make(chan error, 1)
		msgChan <- &SendMsg{
			UserId:     req.UserID,
			GroupID:    req.GroupID,
			Content:    sendContent,
			Type:       "text",
			AtUser:     strings.TrimRight(atUserID, ","),
			ResultChan: ch,
		}
		resultChans = append(resultChans, ch)
	}

	// 等待所有消息发送完成
	for _, ch := range resultChans {
		if err := <-ch; err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"status": "failed",
				"error":  err.Error(),
			})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
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

// jsonUnescapeString 对双重JSON编码的字符串做unescape
// 例如: \\u003c → \u003c (第一次json.Unmarshal) → < (本函数)
func jsonUnescapeString(s string) string {
	if s == "" {
		return s
	}
	var result string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &result); err != nil {
		return s
	}
	return result
}

// getFileExt 从文件名中提取扩展名(不含.)
func getFileExt(fileName string) string {
	idx := strings.LastIndex(fileName, ".")
	if idx == -1 || idx == len(fileName)-1 {
		return ""
	}
	return fileName[idx+1:]
}

// extractFileName 从路径或URL中提取文件名
func extractFileName(s string) string {
	if s == "" {
		return ""
	}
	// 跳过 base64 数据
	if strings.HasPrefix(s, "base64://") || strings.Contains(s, ";base64,") {
		return ""
	}
	// URL 路径
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "file://") {
		if u, err := url.Parse(s); err == nil {
			p := u.Path
			if idx := strings.LastIndex(p, "/"); idx != -1 {
				return p[idx+1:]
			}
			return p
		}
	}
	// 本地文件路径
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		if idx := strings.LastIndexAny(s, "/\\"); idx != -1 {
			return s[idx+1:]
		}
	}
	return s
}

