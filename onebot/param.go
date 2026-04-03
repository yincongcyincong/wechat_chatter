package main

import (
	"encoding/xml"
	"sync"

	"github.com/frida/frida-go/frida"
)

// 全局变量，保持 Frida 脚本对象
var (
	fridaScript *frida.Script
	session     *frida.Session
	device      frida.DeviceInt
	taskId      = int64(0x20000000)
	requestSeq  int64
	myWechatId  = ""

	msgChan = make(chan *SendMsg, 100)

	config = &Config{}

	userID2NicknameMap sync.Map
	userID2FileMsgMap  sync.Map
	pendingTaskMap     sync.Map
	pendingUploadMap   sync.Map
)

type WechatMessage struct {
	GroupId     string     `json:"group_id"`
	SelfID      string     `json:"self_id"`
	UserID      string     `json:"user_id"`
	Sender      *Sender    `json:"sender"`
	Time        int64      `json:"time"`
	PostType    string     `json:"post_type"`
	MessageId   string     `json:"message_id"`
	Message     []*Message `json:"message"`
	MsgResource string     `json:"msgsource"`
	RawMessage  string     `json:"raw_message"`
	ShowContent string     `json:"show_content"`
	MessageType string     `json:"message_type"`
}

type Sender struct {
	UserID   string `json:"user_id"`
	Nickname string `json:"nickname"`
}

type SendMsg struct {
	UserId    string
	GroupID   string
	Content   string
	Type      string
	AtUser    string
	FileData  []byte
	RequestID string
	ResultCh  chan error

	FIleCdnUrl string
	Md5        string
	AesKey     string
	FilePath   string
	FileType   int
}

// SendRequest 请求结构体
type SendRequest struct {
	Message []*Message `json:"message"`
	UserID  string     `json:"user_id"`
	GroupID string     `json:"group_id"`
}

type Message struct {
	Type string           `json:"type"`
	Data *SendRequestData `json:"data"`
}

type SendRequestData struct {
	Id    string `json:"id,omitempty"`
	Text  string `json:"text,omitempty"`
	File  string `json:"file,omitempty"`
	URL   string `json:"url,omitempty"`
	QQ    string `json:"qq,omitempty"`
	Media []byte `json:"media,omitempty"`
}

type Config struct {
	FridaType       string `json:"frida_type"`
	SendURL         string `json:"send_url"`
	ReceiveHost     string `json:"receive_host"`
	FridaGadgetAddr string `json:"frida_gadget_addr"`
	OnebotToken     string `json:"onebot_token"`
	ImagePath       string `json:"image_path"`
	ConnType        string `json:"conn_type"`
	SendInterval    int    `json:"send_interval"`

	WechatConf string `json:"wechat_conf"`
}

// VoiceMsg 对应外层的 <msg> 标签
type VoiceMsg struct {
	XMLName  xml.Name      `xml:"msg"`
	VoiceMsg *VoiceMsgInfo `xml:"voicemsg"`
}

// VoiceMsgInfo 对应内部的 <voicemsg> 标签及其属性
type VoiceMsgInfo struct {
	EndFlag      int    `xml:"endflag,attr"`
	CancelFlag   int    `xml:"cancelflag,attr"`
	ForwardFlag  int    `xml:"forwardflag,attr"`
	VoiceFormat  int    `xml:"voiceformat,attr"`
	VoiceLength  int    `xml:"voicelength,attr"`
	Length       int    `xml:"length,attr"`
	BufID        int    `xml:"bufid,attr"`
	AESKey       string `xml:"aeskey,attr"`
	VoiceURL     string `xml:"voiceurl,attr"`
	VoiceMD5     string `xml:"voicemd5,attr"`
	ClientMsgID  string `xml:"clientmsgid,attr"`
	FromUserName string `xml:"fromusername,attr"`
}

// FileMsg 对应 <msg> 标签
type FileMsg struct {
	XMLName       xml.Name      `xml:"msg"`
	Image         Image         `xml:"img"`
	Emoji         Emoji         `xml:"emoji"`
	Video         VideoMsg      `xml:"videomsg"`
	GameExt       GameExt       `xml:"gameext"`
	AppMsg        AppMsg        `xml:"appmsg"`
	ExtCommonInfo ExtCommonInfo `xml:"extcommoninfo"`
	FromUsername  string        `xml:"fromusername"`
	Scene         string        `xml:"scene"`
	AppInfo       AppInfo       `xml:"appinfo"`
	CommentURL    string        `xml:"commenturl"`
}

// Image 对应 <img> 标签及其属性和子节点
type Image struct {
	// 属性（Attributes）
	AesKey      string `xml:"aeskey,attr"`
	EncryVer    int    `xml:"encryver,attr"`
	ThumbAesKey string `xml:"cdnthumbaeskey,attr"`
	ThumbURL    string `xml:"cdnthumburl,attr"`
	Length      int    `xml:"length,attr"`
	Md5         string `xml:"md5,attr"`
	HDHeight    int    `xml:"cdnhdheight,attr"`
	HDWidth     int    `xml:"cdnhdwidth,attr"`
	MidImgURL   string `xml:"cdnmidimgurl,attr"`

	// 子节点
	SecHashInfo string `xml:"secHashInfoBase64"`
	Live        Live   `xml:"live"`
}

// Live 对应 <live> 标签
type Live struct {
	Duration int    `xml:"duration"`
	Size     int    `xml:"size"`
	FileID   string `xml:"fileid"`
}

type DownloadRequest struct {
	FileID         string `json:"file_id"`
	Media          []byte `json:"media"`
	CDNURL         string `json:"cdn_url"`
	LastAppendTime int64  `json:"last_append_time"`
	FilePath       string `json:"file_path"`
}

type ScriptMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type Emoji struct {
	FromUsername      string `xml:"fromusername,attr"`
	ToUserName        string `xml:"tousername,attr"`
	Type              string `xml:"type,attr"`
	IdBuffer          string `xml:"idbuffer,attr"`
	Md5               string `xml:"md5,attr"`
	Len               string `xml:"len,attr"`
	ProductId         string `xml:"productid,attr"`
	AndroidMd5        string `xml:"androidmd5,attr"`
	AndroidLen        string `xml:"androidlen,attr"`
	S60v3Md5          string `xml:"s60v3md5,attr"`
	S60v3Len          string `xml:"s60v3len,attr"`
	S60v5Md5          string `xml:"s60v5md5,attr"`
	S60v5Len          string `xml:"s60v5len,attr"`
	CdnUrl            string `xml:"cdnurl,attr"`
	DesignerId        string `xml:"designerid,attr"`
	ThumbUrl          string `xml:"thumburl,attr"`
	EncryptUrl        string `xml:"encrypturl,attr"`
	AesKey            string `xml:"aeskey,attr"`
	ExternUrl         string `xml:"externurl,attr"`
	ExternMd5         string `xml:"externmd5,attr"`
	Width             string `xml:"width,attr"`
	Height            string `xml:"height,attr"`
	TpUrl             string `xml:"tpurl,attr"`
	TpAuthKey         string `xml:"tpauthkey,attr"`
	AttachedText      string `xml:"attachedtext,attr"`
	AttachedTextColor string `xml:"attachedtextcolor,attr"`
	LensId            string `xml:"lensid,attr"`
	EmojiAttr         string `xml:"emojiattr,attr"`
	LinkId            string `xml:"linkid,attr"`
	Desc              string `xml:"desc,attr"`
}

type GameExt struct {
	Type    string `xml:"type,attr"`
	Content string `xml:"content,attr"`
}

type AppMsg struct {
	AppID         string        `xml:"appid,attr"`
	SDKVer        string        `xml:"sdkver,attr"`
	Title         string        `xml:"title"`
	Type          string        `xml:"type"`
	Action        string        `xml:"action"`
	AppAttach     AppAttach     `xml:"appattach"`
	MD5           string        `xml:"md5"`
	WebViewShared WebViewShared `xml:"webviewshared"`
}

type AppAttach struct {
	TotalLen          string `xml:"totallen"`
	FileExt           string `xml:"fileext"`
	AttachID          string `xml:"attachid"`
	CdnAttachURL      string `xml:"cdnattachurl"`
	CdnThumbAesKey    string `xml:"cdnthumbaeskey"`
	AesKey            string `xml:"aeskey"`
	EncryVer          string `xml:"encryver"`
	FileKey           string `xml:"filekey"`
	OverwriteNewMsgID string `xml:"overwrite_newmsgid"`
	FileUploadToken   string `xml:"fileuploadtoken"`
}

type WebViewShared struct {
	JsAppID        string `xml:"jsAppId"`
	PublisherReqID string `xml:"publisherReqId"`
}

type ExtCommonInfo struct {
	MediaExpireAt string `xml:"media_expire_at"`
}

type AppInfo struct {
	Version string `xml:"version"`
	AppName string `xml:"appname"`
}

type VideoMsg struct {
	AesKey            string `xml:"aeskey,attr"`            // 视频解密 Key
	CdnVideoUrl       string `xml:"cdnvideourl,attr"`       // 视频 CDN 地址
	CdnThumbAesKey    string `xml:"cdnthumbaeskey,attr"`    // 缩略图解密 Key
	CdnThumbUrl       string `xml:"cdnthumburl,attr"`       // 缩略图 CDN 地址
	Length            int64  `xml:"length,attr"`            // 视频文件大小 (字节)
	PlayLength        int    `xml:"playlength,attr"`        // 播放时长 (秒)
	CdnThumbLength    int    `xml:"cdnthumblength,attr"`    // 缩略图大小
	CdnThumbWidth     int    `xml:"cdnthumbwidth,attr"`     // 缩略图宽度
	CdnThumbHeight    int    `xml:"cdnthumbheight,attr"`    // 缩略图高度
	FromUsername      string `xml:"fromusername,attr"`      // 发送者 ID
	Md5               string `xml:"md5,attr"`               // 视频 MD5
	NewMd5            string `xml:"newmd5,attr"`            // 新版 MD5
	IsPlaceholder     int    `xml:"isplaceholder,attr"`     // 是否占位符
	RawMd5            string `xml:"rawmd5,attr"`            // 原始 MD5
	RawLength         int64  `xml:"rawlength,attr"`         // 原始长度
	CdnRawVideoUrl    string `xml:"cdnrawvideourl,attr"`    // 原始视频 CDN 地址
	CdnRawVideoAesKey string `xml:"cdnrawvideoaeskey,attr"` // 原始视频解密 Key
	OverwriteNewMsgId int64  `xml:"overwritenewmsgid,attr"` // 覆盖消息 ID
	OriginSourceMd5   string `xml:"originsourcemd5,attr"`   // 原始源 MD5
	IsAd              int    `xml:"isad,attr"`              // 是否为广告
}
