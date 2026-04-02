package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}
var conn *websocket.Conn

type OneBotWSMsg struct {
	Action string    `json:"action"`
	Echo   string    `json:"echo"`
	Params *WSParams `json:"params"`
}

type WSParams struct {
	Message interface{} `json:"message"`
	UserID  string      `json:"user_id"`
	GroupID string      `json:"group_id"`
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var err error
	conn, err = upgrader.Upgrade(w, r, nil)
	if err != nil {
		Error("升级失败", "err", err)
		return
	}
	defer conn.Close()

	for {
		m := new(OneBotWSMsg)
		_, msgByte, err := conn.ReadMessage()
		if err != nil {
			Error("读取失败", "err", err)
			break
		}

		Info("收到消息", "msg", string(msgByte))
		err = json.Unmarshal(msgByte, m)
		if err != nil {
			Error("解析失败", "err", err)
			continue
		}

		switch m.Action {
		case "get_login_info":
			err = conn.WriteJSON(map[string]any{
				"echo":   m.Echo,
				"status": "ok",
				"data": map[string]any{
					"user_id":  myWechatId,
					"nickname": myWechatId,
				},
			})
			if err != nil {
				Error("写入失败", "err", err)
				break
			}
		case "get_group_member_info":
			nickname, _ := userID2NicknameMap.Load(m.Params.GroupID + "_" + m.Params.UserID)
			err = conn.WriteJSON(map[string]any{
				"echo":   m.Echo,
				"status": "ok",
				"data": map[string]any{
					"nickname": nickname,
				},
			})
			if err != nil {
				Error("写入失败", "err", err)
				break
			}
		case "send_private_msg", "send_group_msg":
			err = SendWS(m.Params)
			if err != nil {
				Error("发送失败", "err", err)
				break
			}

		}

	}

}

func SendWebSocketMsg(jsonData []byte) {
	defer func() {
		if r := recover(); r != nil {
			Error("ws panic", "err", r, "stack", string(debug.Stack()))
		}
	}()

	if conn == nil {
		Error("连接为空")
		return
	}

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
	err = conn.WriteMessage(websocket.TextMessage, jsonReq)
	if err != nil {
		Error("发送消息失败", "err", err)
		return
	}
}

func SendWS(req *WSParams) error {
	sendContent := ""
	atUserID := ""
	if msg, ok := req.Message.(string); ok {
		sendContent = msg
	} else {
		bytes, err := json.Marshal(req.Message)
		if err != nil {
			Error("JSON 序列化失败", "err", err)
			return err
		}
		msgs := make([]*Message, 0)
		err = json.Unmarshal(bytes, &msgs)
		if err != nil {
			Error("JSON 反序列化失败", "err", err)
			return err
		}

		for _, v := range msgs {
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
					return err
				}
				if err := executeSendMsg(&SendMsg{
					UserId:   req.UserID,
					GroupID:  req.GroupID,
					Type:     v.Type,
					FileData: fileData,
				}); err != nil {
					return err
				}
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
			return err
		}
	}

	return nil
}

func testWebSocket(w http.ResponseWriter, r *http.Request) {
	jsonData, err := io.ReadAll(r.Body)
	if err != nil {
		Error("读取消息失败", "err", err)
		return
	}

	err = conn.WriteMessage(websocket.TextMessage, jsonData)
	if err != nil {
		Error("发送消息失败", "err", err)
		return
	}
}
