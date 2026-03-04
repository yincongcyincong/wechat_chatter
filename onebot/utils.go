package main

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	
	"github.com/wdvxdr1123/go-silk"
)

func SaveBase64Image(base64Data string) (string, string, error) {
	rawContents := base64Data
	if strings.HasPrefix(base64Data, "base64://") {
		rawContents = strings.TrimPrefix(base64Data, "base64://")
	} else if idx := strings.Index(base64Data, ","); idx != -1 {
		rawContents = base64Data[idx+1:]
	}
	
	data, err := base64.StdEncoding.DecodeString(rawContents)
	if err != nil {
		return "", "", fmt.Errorf("base64 decode failed: %v", err)
	}
	salt := []byte(fmt.Sprintf("\n#md5_salt_%d_%d#", time.Now().UnixNano(), rand.Intn(10000)))
	data = append(data, salt...)
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Intn(1000) // 生成 0-999 的随机数
	timestamp := time.Now().Unix()
	fileName := fmt.Sprintf("%d_%d.%s", randomNumber, timestamp, DetectImageFormat(data))
	targetPath := config.ImagePath + fileName
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", "", fmt.Errorf("create directory failed: %v", err)
	}
	
	err = os.WriteFile(targetPath, data, 0644)
	if err != nil {
		return "", "", fmt.Errorf("write file failed: %v", err)
	}
	
	md5Str, err := GetFileMD5(targetPath)
	if err != nil {
		return "", "", fmt.Errorf("get file md5 failed: %v", err)
	}
	
	return targetPath, md5Str, nil
}

func GetFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func DetectImageFormat(data []byte) string {
	if len(data) < 12 {
		return "unknown"
	}
	
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return "jpg"
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
		return "png"
	case bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")):
		return "gif"
	case bytes.HasPrefix(data, []byte{0x42, 0x4D}):
		return "bmp"
	case bytes.HasPrefix(data, []byte("RIFF")) && bytes.HasPrefix(data[8:], []byte("WEBP")):
		return "webp"
	default:
		return "unknown"
	}
}

func EnsureDir(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	
	return err
}

func SaveAudioFile(silkBytes []byte) (path string, err error) {
	mp3Bytes, err := SilkToMp3(silkBytes)
	if err != nil {
		return "", err
	}
	
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Intn(1000)
	timestamp := time.Now().Unix()
	fileName := fmt.Sprintf("%d_%d.mp3", randomNumber, timestamp)
	targetPath := filepath.Dir(exePath) + "/audio/" + fileName
	err = os.WriteFile(targetPath, mp3Bytes, 0644)
	if err != nil {
		return "", err
	}
	
	return targetPath, nil
}

func SilkToMp3(silkBytes []byte) ([]byte, error) {
	var pcm, err = silk.DecodeSilkBuffToPcm(silkBytes, 16000)
	if err != nil {
		return nil, err
	}
	
	cmd := exec.Command("ffmpeg",
		"-f", "s16le",
		"-ar", "16000",
		"-ac", "1",
		"-i", "pipe:0",
		"-codec:a", "libmp3lame",
		"-b:a", "192k",
		"-f", "mp3",
		"pipe:1",
	)
	cmd.Stdin = bytes.NewReader(pcm)
	
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg error: %v, details: %s", err, stderr.String())
	}
	
	return out.Bytes(), nil
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
		if msg.Type == "record" {
			path, err := SaveAudioFile(msg.Data.Media)
			if err != nil {
				Error("保存音频失败", "err", err)
				return nil, err
			}
			msg.Data.URL = "file://" + path
			msg.Data.Media = nil
		} else if msg.Type == "image" {
			var fileMsg FileMsg
			err = xml.Unmarshal([]byte(msg.Data.Text), &fileMsg)
			if err != nil {
				Error("XML解析失败", "err", err)
				return nil, err
			}
			
			// 如果有图片等待图片下载完成再处理
			if len(msg.Data.Media) == 0 {
				if downloadMsgInter, ok := userID2FileMsgMap.Load(fileMsg.Image.ThumbURL); ok {
					downloadReq := downloadMsgInter.(*DownloadRequest)
					aesKey, _ := hex.DecodeString(fileMsg.Image.ThumbAesKey)
					path, err := GetImagePath(downloadReq.Media, aesKey)
					if err != nil {
						Error("获取图片路径失败", "err", err)
						return nil, err
					}
					msg.Data.URL = "file://" + path
					userID2FileMsgMap.Delete(fileMsg.Image.ThumbURL)
				}
			}
		}
	}
	return json.Marshal(m)
}

func GetImagePath(data []byte, key []byte) (string, error) {
	block, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(data))
	bs := block.BlockSize()
	for i := 0; i < len(data); i += bs {
		block.Decrypt(decrypted[i:i+bs], data[i:i+bs])
	}
	
	if bytes.HasPrefix(decrypted, []byte{0xFF, 0xD8, 0xFF}) {
		return SaveImageToFile("jpg", decrypted)
	} else if bytes.HasPrefix(decrypted, []byte{0x89, 0x50, 0x4E, 0x47}) {
		return SaveImageToFile("png", decrypted)
	} else if bytes.HasPrefix(decrypted, []byte("GIF89a")) || bytes.HasPrefix(decrypted, []byte("GIF87a")) {
		return SaveImageToFile("gif", decrypted)
	} else if bytes.HasPrefix(decrypted, []byte{0x42, 0x4D}) {
		return SaveImageToFile("bmp", decrypted)
	}
	
	return "", fmt.Errorf("无法解析的图像数据")
}

func SaveImageToFile(ext string, data []byte) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Intn(1000)
	timestamp := time.Now().Unix()
	fileName := fmt.Sprintf("%d_%d.%s", randomNumber, timestamp, ext)
	targetPath := filepath.Dir(exePath) + "/image/" + fileName
	err = os.WriteFile(targetPath, data, 0644)
	if err != nil {
		return "", err
	}
	
	return targetPath, nil
}
