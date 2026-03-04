package main

import (
	"encoding/json"
)

func Download(rawMsg []byte) error {
	downloadReq := new(DownloadRequest)
	err := json.Unmarshal(rawMsg, downloadReq)
	if err != nil {
		Error("JSON解析失败", "err", err)
		return err
	}
	
	Info("下载文件", "file_id", downloadReq.FileID, "media_len", len(downloadReq.Media), "cdn_url", downloadReq.CDNURL[:10])
	if downloadReqInter, ok := userID2FileMsgMap.Load(downloadReq.CDNURL); ok {
		downloadReq = downloadReqInter.(*DownloadRequest)
		downloadReq.Media = append(downloadReq.Media, downloadReq.Media...)
	} else {
		userID2FileMsgMap.Store(downloadReq.CDNURL, downloadReq)
	}
	
	return nil
}
