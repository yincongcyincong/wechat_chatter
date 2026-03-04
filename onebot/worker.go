package main

import (
	"context"
	"runtime/debug"
	"sync/atomic"
	"time"
)

func SendWorker() {
	defer func() {
		if err := recover(); err != nil {
			Error("SendWorker panic", "err", err, "stack", string(debug.Stack()))
			go SendWorker()
		}
	}()
	
	for {
		select {
		case <-finishChan:
			Info("收到完成信号")
		case m, ok := <-msgChan:
			if !ok {
				return
			}
			SendWechatMsg(m)
		}
	}
}

func SendWechatMsg(m *SendMsg) {
	time.Sleep(time.Duration(config.SendInterval) * time.Millisecond)
	currTaskId := atomic.AddInt64(&taskId, 1)
	Info("📩 收到任务", "task_id", currTaskId)
	
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	targetId := m.UserId
	if m.GroupID != "" && targetId == "" {
		targetId = m.GroupID
	}
	
	switch m.Type {
	case "text":
		result := fridaScript.ExportsCall("triggerSendTextMessage", currTaskId, targetId, m.Content, m.AtUser)
		Info("📩 发送文本任务执行结果", "result", result, "task_id", currTaskId, "target_id", targetId, "content", m.Content, "at_user", m.AtUser)
	case "image":
		targetPath, md5Str, err := SaveBase64Image(m.Content)
		if err != nil {
			Error("保存图片失败", "err", err)
			return
		}
		
		result := fridaScript.ExportsCall("triggerUploadImg", targetId, md5Str, targetPath)
		Info("📩 上传图片任务执行结果n", "result", result, "target_id", targetId, "md5", md5Str, "path", targetPath)
	case "send_image":
		result := fridaScript.ExportsCall("triggerSendImgMessage", currTaskId, myWechatId, targetId)
		Info("📩 发送图片任务执行结果", "result", result, "task_id", currTaskId, "wechat_id", myWechatId, "target_id", targetId)
	}
	
	select {
	case <-ctx.Done():
		Info("任务执行超时！", "taskId", currTaskId)
	case <-finishChan:
		Info("收到完成信号，任务完成", "taskId", currTaskId)
	}
}
