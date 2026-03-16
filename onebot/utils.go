package main

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	fileName := fmt.Sprintf("%d_%d.%s", randomNumber, timestamp, DetectFileFormat(data))
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

func GetFilePath(data []byte, key []byte) (string, error) {
	block, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(data))
	bs := block.BlockSize()
	for i := 0; i < len(data); i += bs {
		block.Decrypt(decrypted[i:i+bs], data[i:i+bs])
	}
	
	ext := DetectFileFormat(decrypted)
	if ext == "unknown" {
		return "", fmt.Errorf("无法解析的文件数据")
	}
	
	return SaveFileToFile(ext, decrypted)
}

// DetectFileFormat 检测文件格式，返回扩展名
func DetectFileFormat(data []byte) string {
	if len(data) < 8 {
		return "unknown"
	}
	
	switch {
	// 视频格式
	case bytes.HasPrefix(data, []byte{0x00, 0x00, 0x00}): // MP4/MOV 通常以 ftyp 开头，后面是具体类型
		if len(data) > 4 {
			switch string(data[4:8]) {
			case "ftyp", "moov", "mdat", "wide", "free":
				return "mp4"
			case "isom", "mp41", "mp42", "M4V ", "M4A ", "M4P ":
				return "mp4"
			}
		}
	case bytes.HasPrefix(data, []byte("FLV\x01")): // FLV
		return "flv"
	case bytes.HasPrefix(data, []byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11}): // ASF/WMV/WMA
		if len(data) > 8 && bytes.HasPrefix(data[8:], []byte{0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C}) {
			return "wmv"
		}
	
	// 图片格式
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return "jpg"
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
		return "png"
	case bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")):
		return "gif"
	case bytes.HasPrefix(data, []byte{0x42, 0x4D}):
		return "bmp"
	case bytes.HasPrefix(data, []byte("RIFF")) && len(data) > 8 && bytes.HasPrefix(data[8:], []byte("WEBP")):
		return "webp"
	
	// 文档格式
	case bytes.HasPrefix(data, []byte("%PDF")):
		return "pdf"
	
	// Office 2007+ 格式 (docx, xlsx, pptx 都是 ZIP 格式)
	case bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}):
		return detectOfficeFormat(data)
	
	// Office 97-2003 格式 (OLE2 格式)
	case bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		return detectLegacyOfficeFormat(data)
	
	// 压缩文件
	case bytes.HasPrefix(data, []byte("Rar!\x1a\x07")):
		return "rar"
	case bytes.HasPrefix(data, []byte("7z\xBC\xAF\x27\x1C")):
		return "7z"
	
	default:
		return "unknown"
	}
	
	return "unknown"
}

// detectOfficeFormat 检测 Office 2007+ 文件具体类型
func detectOfficeFormat(data []byte) string {
	// 查找 ZIP 内的特定文件来区分类型
	if bytes.Contains(data, []byte("[Content_Types].xml")) {
		if bytes.Contains(data, []byte("word/")) {
			return "docx"
		}
		if bytes.Contains(data, []byte("xl/")) {
			return "xlsx"
		}
		if bytes.Contains(data, []byte("ppt/")) {
			return "pptx"
		}
	}
	// 普通 ZIP 文件
	return "zip"
}

// detectLegacyOfficeFormat 检测 Office 97-2003 文件具体类型
func detectLegacyOfficeFormat(data []byte) string {
	// 通过文件内容特征判断
	if bytes.Contains(data, []byte("Word.Document")) {
		return "doc"
	}
	if bytes.Contains(data, []byte("Excel.Sheet")) {
		return "xls"
	}
	if bytes.Contains(data, []byte("PowerPoint.Show")) {
		return "ppt"
	}
	return "ole"
}

// SaveFileToFile 通用文件保存函数
func SaveFileToFile(ext string, data []byte) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Intn(1000)
	timestamp := time.Now().Unix()
	
	// 根据文件类型选择保存目录
	dir := "file"
	if ext == "jpg" || ext == "png" || ext == "gif" || ext == "bmp" || ext == "webp" {
		dir = "image"
	}
	
	fileName := fmt.Sprintf("%d_%d.%s", randomNumber, timestamp, ext)
	targetPath := filepath.Dir(exePath) + "/" + dir + "/" + fileName
	
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return "", err
	}
	
	err = os.WriteFile(targetPath, data, 0644)
	if err != nil {
		return "", err
	}
	
	return targetPath, nil
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

func GetWeChatPID() (int, error) {
	cmd := exec.Command("pgrep", "-x", "WeChat")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("未发现正在运行的微信进程")
	}
	
	return strconv.Atoi(strings.TrimSpace(string(output)))
}

func DownloadFile(urlStr string) ([]byte, error) {
	if urlStr == "" {
		return nil, errors.New("url is empty")
	}
	
	// 解析 URL 以判断协议
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, errors.New("invalid URL format: " + err.Error())
	}
	
	// 处理 file:// 协议
	if parsedURL.Scheme == "file" {
		// 去除 "file://" 前缀，得到本地文件路径
		filePath := strings.TrimPrefix(urlStr, "file://")
		// 对于 Windows 路径可能需要额外处理，但你的路径是 macOS/Linux 格式
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, errors.New("failed to read local file: " + err.Error())
		}
		return data, nil
	}
	
	client := &http.Client{}
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to download file: " + resp.Status)
	}
	
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	return data, nil
}

// DetectAndSaveImage 自动检测图片格式并保存到本地
func DetectAndSaveImage(data []byte) (string, error) {
	// 先检测图片格式
	ext := DetectFileFormat(data)
	if ext == "unknown" {
		return "", fmt.Errorf("无法识别的图片格式")
	}
	
	// 调用保存函数
	return SaveImageToFile(ext, data)
}
