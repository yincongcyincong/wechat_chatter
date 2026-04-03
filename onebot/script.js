var moduleName = "wechat.dylib";
var baseAddr = Process.findModuleByName(moduleName).base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

// -------------------------基础函数分区-------------------------
function toVarint(n) {
    let res = [];
    while (n >= 128) {
        res.push((n & 0x7F) | 0x80); // 取后7位，最高位置1
        n = n >> 7;                 // 右移7位
    }
    res.push(n); // 最后一位最高位为0
    return res;
}


function stringToHexArray(str) {
    var utf8Str = unescape(encodeURIComponent(str));
    var arr = [];
    for (var i = 0; i < utf8Str.length; i++) {
        arr.push(utf8Str.charCodeAt(i)); // 获取字符的 ASCII 码 (即十六进制值)
    }
    return arr;
}


function generateRandom5ByteVarint() {
    let res = [];

    // 前 4 个字节：最高位(bit 7)必须是 1，低 7 位随机
    for (let i = 0; i < 4; i++) {
        let random7Bit = Math.floor(Math.random() * 128);
        res.push(random7Bit | 0x80); // 强制设置最高位为 1
    }

    // 第 5 个字节：最高位必须是 0，为了确保不变成 4 字节，低 7 位不能全为 0
    let lastByte = Math.floor(Math.random() * 127) + 1;
    res.push(lastByte & 0x7F); // 确保最高位为 0

    return res;
}


// 辅助函数：Protobuf Varint 编码 (对应 get_varint_timestamp_bytes)
function getVarintTimestampBytes() {
    let ts = Math.floor(Date.now() / 1000);
    let encodedBytes = [];
    let tempTs = ts >>> 0; // 强制转为 32位 无符号整数

    while (true) {
        let byte = tempTs & 0x7F;
        tempTs >>>= 7;
        if (tempTs !== 0) {
            encodedBytes.push(byte | 0x80);
        } else {
            encodedBytes.push(byte);
            break;
        }
    }
    return encodedBytes;
}

function patchString(addr, plainStr) {
    const bytes = [];
    for (let i = 0; i < plainStr.length; i++) {
        bytes.push(plainStr.charCodeAt(i));
    }

    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0);
}

function generateAESKey() {
    const chars = 'abcdef0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

function getProtobufRawBytes(pBuffer, scanSize) {
    const tags = [0x12, 0x1A, 0x2A, 0x42, 0x52, 0x5A];
    let uint8Array;

    try {
        const mem = pBuffer.readByteArray(scanSize);
        if (!mem) return [];
        uint8Array = new Uint8Array(mem);
    } catch (e) {
        console.error("读取内存失败: " + e);
        return [];
    }

    let finalResults = [];

    let i = 0x1a;
    tags.forEach(targetTag => {
        let found = false;
        for (; i < uint8Array.length; i++) {
            if (uint8Array[i] === targetTag) {
                // 1. 解析 Varint 长度 (支持 1-5 字节长度标识)
                let length = 0;
                let shift = 0;
                let bytesReadForLen = 0;
                i = i + 1;

                let lenNum = 0;
                while (i < uint8Array.length) {
                    let b = uint8Array[i];
                    length |= (b & 0x7F) << shift;
                    bytesReadForLen++;
                    i++;
                    lenNum++;
                    if (!(b & 0x80)) break;
                    shift += 7;
                }

                // 2. 截取原始 Byte 数据
                if (i + length <= uint8Array.length) {
                    let addNum = 0
                    if (targetTag === 0x12 || targetTag === 0x1A || targetTag === 0x2A) {
                        addNum = lenNum + 1;
                    }
                    let rawData = uint8Array.slice(i, i + length);
                    if (targetTag === 0x42) {
                        finalResults.push(rawData);
                    } else {
                        finalResults.push(getCleanString(rawData));
                    }
                    i += length;
                } else {
                    finalResults.push(null); // 长度越界
                }

                found = true;
                break; // 找到第一个匹配的 Tag 就跳出
            }
        }
        if (!found) finalResults.push(null); // 未找到该 Tag
    });


    for (; i < uint8Array.length; i++) {
        if (uint8Array[i] === 0x60 && i + 10 <= uint8Array.length) {
            finalResults.push(uint8Array.slice(i + 1, i + 10))
        }
    }

    return finalResults;
}

function getCleanString(uint8Array) {
    var out = "";
    var i = 0;
    var len = uint8Array.length;

    while (i < len) {
        var c = uint8Array[i++];

        // 1. 处理单字节 (ASCII: 0xxxxxxx)
        if (c < 0x80) {
            // 只保留可见字符 (Space 32 到 ~ 126)
            if (c >= 32 && c <= 126) {
                out += String.fromCharCode(c);
            }
        }
        // 2. 处理双字节 (110xxxxx 10xxxxxx)
        else if ((c & 0xE0) === 0xC0 && i < len) {
            var c2 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80) {
                // 这种通常是特殊拉丁字母等，按需保留
                var charCode = ((c & 0x1F) << 6) | (c2 & 0x3F);
                out += String.fromCharCode(charCode);
            } else {
                i--;
            }
        }
        // 3. 处理三字节 (1110xxxx 10xxxxxx 10xxxxxx) -> 绝大多数汉字在此
        else if ((c & 0xF0) === 0xE0 && i + 1 < len) {
            var c2 = uint8Array[i++];
            var c3 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80 && (c3 & 0xC0) === 0x80) {
                var charCode = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
                if (
                    (charCode >= 0x4E00 && charCode <= 0x9FA5) || // 基本汉字
                    (charCode >= 0x3000 && charCode <= 0x303F) || // 常用中文标点 (。，、)
                    (charCode >= 0xFF00 && charCode <= 0xFFEF) || // 全角符号/标点 (！：？)
                    (charCode >= 0x2000 && charCode <= 0x206F) || // 常用标点扩展 (含 \u2005)
                    (charCode >= 0x3400 && charCode <= 0x4DBF)    // 扩展 A 区汉字
                ) {
                    out += String.fromCharCode(charCode);
                }
            } else {
                i -= 2;
            }
        } else if ((c & 0xF8) === 0xF0 && i + 2 < len) {
            var c2 = uint8Array[i++];
            var c3 = uint8Array[i++];
            var c4 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80 && (c3 & 0xC0) === 0x80 && (c4 & 0xC0) === 0x80) {
                // 计算 Unicode 码点
                var codePoint = ((c & 0x07) << 18) | ((c2 & 0x3F) << 12) | ((c3 & 0x3F) << 6) | (c4 & 0x3F);

                // Emoji 范围通常在 U+1F000 到 U+1F9FF 之间
                if (codePoint >= 0x1F000 && codePoint <= 0x1FADF) {
                    // 使用 fromCodePoint 处理 4 字节字符
                    out += String.fromCodePoint(codePoint);
                }
            } else {
                i -= 3;
            }
        }
    }
    return out;
}

function protobufVarintToNumberString(uint8Array) {
    let result = BigInt(0);
    let shift = BigInt(0);

    for (let i = 0; i < uint8Array?.length; i++) {
        const byte = uint8Array[i];

        // 1. 取出低 7 位并累加到结果中
        // (BigInt(byte & 0x7F) << shift)
        result += BigInt(byte & 0x7F) << shift;

        // 2. 检查最高位 (MSB)。如果为 0，说明这个数字结束了
        if ((byte & 0x80) === 0) {
            return result.toString();
        }

        // 3. 准备处理下一个 7 位
        shift += BigInt(7);
    }

    return result.toString();
}

function generateBytes(n) {
    // 生成随机字符串
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';

    for (let i = 0; i < n; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return stringToHexArray(result);
}

// -------------------------基础函数分区-------------------------

// -------------------------全局变量分区-------------------------

// 文本消息全局变量
// 文本消息全局变量
var textCallbackFuncAddr = baseAddr.add({{.textCallbackFuncAddr}});
var protobufAddr = textCallbackFuncAddr.add(0x40);
var patchTextProtobufAddr = textCallbackFuncAddr.add(0x20);
var patchTextProtobufByte
var patchTextProtobufDeleteAddr = textCallbackFuncAddr.add(0x5C);
var patchTextProtobufDeleteByte
var textCgiAddr = ptr(0);
var sendTextMessageAddr = ptr(0);
var textMessageAddr = ptr(0);
var textProtoX1PayloadAddr = ptr(0);
var sendMessageCallbackFunc = baseAddr.add({{.sendMessageCallbackFunc}});


// 双方公共使用的地址
var triggerX1Payload;
var triggerX0;
var req2bufEnterAddr = baseAddr.add({{.req2bufEnterAddr}});
var req2bufExitAddr = baseAddr.add({{.req2bufExitAddr}});
var sendFuncAddr = baseAddr.add({{.sendFuncAddr}});
var insertMsgAddr = ptr(0);
var sendMsgType = "";
var buf2RespAddr = baseAddr.add({{.buf2RespAddr}});

// 图片消息全局变量
var imageCallbackFuncAddr = baseAddr.add({{.imageCallbackFuncAddr}});
var imgProtobufAddr = imageCallbackFuncAddr.add(0x50);
var patchImgProtobufFunc1 = imageCallbackFuncAddr.add(0x10);
var patchImgProtobufFunc1Byte;
var patchImgProtobufFunc2 = imageCallbackFuncAddr.add(0x30);
var patchImgProtobufFunc2Byte;
var imgProtobufDeleteAddr = imageCallbackFuncAddr.add(0x6c);
var imgProtobufDeleteAddrByte;

// 视频消息全局变量
var videoCallbackFuncAddr = baseAddr.add({{.videoCallbackFuncAddr}});
var videoProtobufAddr = videoCallbackFuncAddr.add(0x50);
var patchVideoProtobufFunc1 = videoCallbackFuncAddr.add(0x10);
var patchVideoProtobufFunc1Byte;
var patchVideoProtobufFunc2 = videoCallbackFuncAddr.add(0x30);
var patchVideoProtobufFunc2Byte;
var videoProtobufDeleteAddr = videoCallbackFuncAddr.add(0x6c);
var videoProtobufDeleteAddrByte;

var uploadImageAddr = baseAddr.add({{.uploadImageAddr}});
var cndOnCompleteAddr = baseAddr.add({{.cndOnCompleteAddr}});
var imgMessageCallbackFunc = baseAddr.add({{.imgMessageCallbackFunc}});
var videoMessageCallbackFunc = baseAddr.add({{.videoMessageCallbackFunc}});

var uploadGetCallbackWrapperAddr = baseAddr.add({{.uploadGetCallbackWrapperAddr}});
var uploadGetCallbackWrapperFuncAddr = baseAddr.add({{.uploadGetCallbackWrapperFuncAddr}});
var uploadOnCompleteAddr = baseAddr.add({{.uploadOnCompleteAddr}});
var uploadOnCompleteFuncAddr = baseAddr.add({{.uploadOnCompleteFuncAddr}});
var downloadImagAddr = baseAddr.add({{.downloadImagAddr}});
var startDownloadMedia = baseAddr.add({{.startDownloadMedia}})
var downloadFileAddr = baseAddr.add({{.downloadFileAddr}})
var downloadVideoAddr = baseAddr.add({{.downloadVideoAddr}})

var downloadGlobalX0;
var downloadFileX1 = ptr(0)
var fileIdAddr = ptr(0)
var fileMd5Addr = ptr(0)
var downloadAesKeyAddr = ptr(0)
var filePathAddr = ptr(0)
var fileCdnUrlAddr = ptr(0)
var uploadImageX1 = ptr(0);
var imgCgiAddr = ptr(0);
var sendImgMessageAddr = ptr(0);
var imgMessageAddr = ptr(0);
var imgProtoX1PayloadAddr = ptr(0);
var uploadGlobalX0 = ptr(0)
var uploadFunc1Addr = ptr(0)
var uploadFunc2Addr = ptr(0)
var imageIdAddr = ptr(0)
var md5Addr = ptr(0)
var uploadRequestIdGlobal = ""
var uploadAesKeyAddr = ptr(0)
var ImagePathAddr1 = ptr(0)
var uploadCallback = ptr(0)

var videoCgiAddr = ptr(0);
var sendVideoMessageAddr = ptr(0);
var videoMessageAddr = ptr(0);
var videoProtoX1PayloadAddr = ptr(0);
var uploadVideoX1 = ptr(0);
var videoIdAddr = ptr(0);
var videoPathAddr1 = ptr(0)


// -------------------------上传队列 (解决并发问题)-------------------------
// 图片上传完成队列 - 存储 {cdnKey, aesKey, md5Key, targetId}
var imageUploadQueue = [];
// 视频上传完成队列 - 存储 {cdnKey, aesKey, md5Key, videoIdentity, targetId}
var videoUploadQueue = [];

// 从队列中获取最早的可用上传信息
function getImageUploadInfo() {
    if (imageUploadQueue.length > 0) {
        return imageUploadQueue.shift();
    }
    return null;
}

function getVideoUploadInfo() {
    if (videoUploadQueue.length > 0) {
        return videoUploadQueue.shift();
    }
    return null;
}

function pushImageUploadInfo(info) {
    imageUploadQueue.push(info);
    console.log("[+] 图片上传信息已入队，当前队列长度:", imageUploadQueue.length);
}

function pushVideoUploadInfo(info) {
    videoUploadQueue.push(info);
    console.log("[+] 视频上传信息已入队，当前队列长度:", videoUploadQueue.length);
}

// -------------------------上传队列 end-------------------------

// 发送消息的全局变量
var taskIdGlobal = 0x20000090 // 最好比较大，不和原始的微信消息重复
var receiverGlobal = "wxid_"
var contentGlobal = "";
var senderGlobal = "wxid_"
var lastSendTime = 0;
var atUserGlobal = "";

const fileCp = generateBytes(16)

// -------------------------全局变量分区-------------------------


// -------------------------发送文本消息分区-------------------------
// 初始化进行内存的分配
function setupSendTextMessageDynamic() {
    console.log("[+] Starting Dynamic Message Patching...");

    // 1. 动态分配内存块（按需分配大小）
    // 分配原则：字符串给 64-128 字节，结构体按实际大小分配
    textCgiAddr = Memory.alloc(128);
    sendTextMessageAddr = Memory.alloc(256);
    textMessageAddr = Memory.alloc(256);

    // A. 写入字符串内容
    patchString(textCgiAddr, "/cgi-bin/micromsg-bin/newsendmsg");

    // B. 构建 sendTextMessageAddr 结构体 (X24 基址位置)
    sendTextMessageAddr.add(0x00).writeU64(0);
    sendTextMessageAddr.add(0x08).writeU64(0);
    sendTextMessageAddr.add(0x10).writeU64(0);
    sendTextMessageAddr.add(0x18).writeU64(1);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x28).writePointer(textMessageAddr); // 指向动态分配的 Message

    // console.log(" [+] sendTextMessageAddr Object: ", hexdump(sendTextMessageAddr, {
    //     offset: 0,
    //     length: 48,
    //     header: true,
    //     ansi: true
    // }));

    // C. 构建 Message 结构体
    textMessageAddr.add(0x00).writePointer(sendMessageCallbackFunc);
    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    textMessageAddr.add(0x0c).writeU32(0x20a);
    textMessageAddr.add(0x10).writeU64(0x3);
    textMessageAddr.add(0x18).writePointer(textCgiAddr);
    textMessageAddr.add(0x20).writeU64(uint64("0x20"));

    // console.log(" [+] textMessageAddr Object: ", hexdump(textMessageAddr, {
    //     offset: 0,
    //     length: 64,
    //     header: true,
    //     ansi: true
    // }));

    console.log("[+] Dynamic Memory Setup Complete. - Message Object: " + textMessageAddr);
    patchTextProtobufByte = patchTextProtobufAddr.readByteArray(4);
    patchTextProtobufDeleteByte = patchTextProtobufDeleteAddr.readByteArray(4);
}

setImmediate(setupSendTextMessageDynamic);


function patchTextProtoBuf() {

    Interceptor.attach(textCallbackFuncAddr, {
        onEnter: function (args) {
            var firstValue = this.context.sp.readU32();
            if (firstValue === taskIdGlobal) {
                if (patchTextProtobufAddr.readU32() !== 3573751839) {
                    Memory.patchCode(patchTextProtobufAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchTextProtobufAddr});
                        cw.putNop();
                        cw.flush();
                    });
                    Memory.patchCode(patchTextProtobufDeleteAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchTextProtobufDeleteAddr});
                        cw.putNop();
                        cw.flush();
                    });
                }
            } else {
                if (patchTextProtobufAddr.readU32() === 3573751839) {
                    Memory.patchCode(patchTextProtobufAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchTextProtobufAddr});
                        cw.putBytes(new Uint8Array(patchTextProtobufByte));
                        cw.flush();
                    });
                    Memory.patchCode(patchTextProtobufDeleteAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchTextProtobufDeleteAddr});
                        cw.putBytes(new Uint8Array(patchTextProtobufDeleteByte));
                        cw.flush();
                    });
                }

            }
        }
    })

}

setImmediate(patchTextProtoBuf);

function triggerSendTextMessage(taskId, receiver, content, atUser) {
    // console.log("[+] Manual Trigger Started...");
    if (!taskId || !receiver || !content) {
        console.error("[!] taskId or Receiver or Content is empty!");
        return "fail";
    }

    // 获取当前时间戳 (秒)
    const timestamp = Math.floor(Date.now() / 1000);
    lastSendTime = timestamp
    taskIdGlobal = taskId;
    receiverGlobal = receiver;
    contentGlobal = content;
    atUserGlobal = atUser
    console.log("taskIdGlobal: " + taskIdGlobal + ", receiverGlobal: " + receiverGlobal + ", contentGlobal: " + contentGlobal + ", atUserGlobal: " + atUserGlobal);

    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);

    const payloadData = [
        0x0A, 0x02, 0x00, 0x00,                         // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08
        0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x10
        0x40, 0xec, 0x0e, 0x12, 0x01, 0x00, 0x00, 0x00, // 0x18
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x28
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // 0x38
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0x40
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA, // 0x48
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, // 0x50
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58
        0x0A, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D, // 0x68 default-
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B, // 0x70 longlink
        0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10, // 0x78
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA8
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xB0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xB8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x130
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x138
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x138
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x140
        0x01, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // 0x188
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
    ];
    triggerX1Payload.writeU32(taskIdGlobal);
    triggerX1Payload.add(0x04).writeByteArray(payloadData);
    triggerX1Payload.add(0x18).writePointer(textCgiAddr);
    triggerX1Payload.add(0xb8).writePointer(triggerX1Payload.add(0xc0));
    triggerX1Payload.add(0x190).writePointer(triggerX1Payload.add(0x198));
    sendMsgType = "text"

    console.log("finished init text payload")
    const MMStartTask = new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);

    // 5. 调用函数
    try {
        return MMStartTask(triggerX0, triggerX1Payload);
    } catch (e) {
        console.error(`[!] Error trigger  MMStartTask ${sendFuncAddr} with args: (${triggerX0}) (${triggerX1Payload}),   during execution: ` + e);
        return "fail";
    }
}

function AttachSendFunc() {
    Interceptor.attach(sendFuncAddr.add(0x10), {
        onEnter: function (args) {

            if (triggerX1Payload) {
                return
            }

            triggerX0 = this.context.x0;
            triggerX1Payload = this.context.x1;
            console.log(`[+] 捕获到 StartTask 调用，X0地址：${triggerX0}, Payload 地址: ${triggerX1Payload}`);
        }
    })
}

setImmediate(AttachSendFunc);

// 拦截 SendTextProto 编码逻辑，注入自定义 Payload
function attachSendTextProto() {
    textProtoX1PayloadAddr = Memory.alloc(3096);
    console.log("[+] Frida 分配的 Payload 地址: " + textProtoX1PayloadAddr);

    Interceptor.attach(protobufAddr, {
        onEnter: function (args) {

            var sp = this.context.sp;
            var firstValue = sp.readU32();
            if (firstValue !== taskIdGlobal) {
                console.log("[+] Protobuf 拦截未命中，跳过...");
                return;
            }
            console.log(`[+] 正在注入 Protobuf Payload content: ${contentGlobal}, receiver: ${receiverGlobal}, atUser: ${atUserGlobal}`);

            const type = [0x08, 0x01, 0x12]
            const receiverHeader = [0x0A, receiverGlobal.length + 2, 0x0A, receiverGlobal.length];
            const receiverProto = stringToHexArray(receiverGlobal);
            const contentProto = stringToHexArray(contentGlobal);
            const contentHeader = [0x12, ...toVarint(contentProto.length)];
            const tsHeader = [0x18, 0x01, 0x20];
            const tsBytes = getVarintTimestampBytes();
            const msgIdHeader = [0x28]
            const msgId = generateRandom5ByteVarint()

            const htmlUpperPart = [0x3C, 0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x3E]
            let atUserHeader = []
            if (atUserGlobal) {
                atUserHeader = atUserHeader.concat([0x3C, 0x61, 0x74, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x69, 0x73, 0x74, 0x3e]).concat(stringToHexArray(atUserGlobal)).concat([0x3C, 0x2F, 0x61, 0x74, 0x75, 0x73, 0x65, 0x72, 0x6C, 0x69, 0x73, 0x74, 0x3E])
            }
            const htmlLowerPart = [0x3C, 0x61, 0x6C, 0x6E, 0x6F,
                0x64, 0x65, 0x3E, 0x3C, 0x66, 0x72, 0x3E, 0x31,
                0x3C, 0x2F, 0x66, 0x72, 0x3E, 0x3C, 0x2F, 0x61,
                0x6C, 0x6E, 0x6F, 0x64, 0x65, 0x3E, 0x3C, 0x2F,
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72,
                0x63, 0x65, 0x3E, 0x00]

            const htmlHeader = [0x32, htmlUpperPart.length + atUserHeader.length + htmlLowerPart.length]


            const valueLen = toVarint(receiverHeader.length + receiverProto.length + contentHeader.length +
                contentProto.length + tsHeader.length + tsBytes.length + msgIdHeader.length + msgId.length + htmlHeader.length +
                htmlUpperPart.length + atUserHeader.length + htmlLowerPart.length)

            // 合并数组
            const finalPayload = type.concat(valueLen).concat(receiverHeader).concat(receiverProto).concat(contentHeader).concat(contentProto).concat(tsHeader).concat(tsBytes).concat(msgIdHeader).concat(msgId).concat(htmlHeader).concat(htmlUpperPart).concat(atUserHeader).concat(htmlLowerPart);

            textProtoX1PayloadAddr.writeByteArray(finalPayload);
            this.context.x1 = textProtoX1PayloadAddr;
            this.context.x2 = ptr(finalPayload.length);

            // console.log("[+] 文本寄存器修改完成: X1=" + this.context.x1 + ", X2=" + this.context.x2, hexdump(textProtoX1PayloadAddr, {
            //     offset: 0,
            //     length: 128,
            //     header: true,
            //     ansi: true
            // }));
        },
    });
}

setImmediate(attachSendTextProto);

// -------------------------发送文本消息分区-------------------------


// -------------------------Req2Buf公共部分分区-------------------------
function attachReq2buf() {
    console.log("[+] Target Req2buf enter Address: " + req2bufEnterAddr);

    // 2. 开始拦截
    Interceptor.attach(req2bufEnterAddr, {
        onEnter: function (args) {
            if (!this.context.x1.equals(taskIdGlobal)) {
                return;
            }

            console.log("[+] 已命中目标Req2Buf地址 taskId:" + taskIdGlobal + "base:" + baseAddr);

            // 3. 获取 X24 寄存器的值
            const x24_base = this.context.x24;
            insertMsgAddr = x24_base.add(0x60);
            console.log("[+] 当前 Req2Buf X24 基址: " + x24_base + " sendMsgType:" + sendMsgType);

            if (sendMsgType === "text") {
                insertMsgAddr.writePointer(sendTextMessageAddr);
                console.log("[+] 发送文本消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendTextMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "img") {
                insertMsgAddr.writePointer(sendImgMessageAddr);
                console.log("[+] 发送图片消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendImgMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "video") {
                insertMsgAddr.writePointer(sendVideoMessageAddr);
                console.log("[+] 发送视频消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendVideoMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            }
        }
    });

    // 在出口处拦截req2buf，把insertMsgAddr设置为0，避免被垃圾回收导致整个程序崩溃
    console.log("[+] Target Req2buf leave Address: " + req2bufExitAddr);
    Interceptor.attach(req2bufExitAddr, {
        onEnter: function (args) {
            if (!this.context.x25.equals(taskIdGlobal)) {
                return;
            }
            const finishedTaskId = taskIdGlobal;
            const finishedSendType = sendMsgType;
            insertMsgAddr.writeU64(0x0);
            console.log("[+] 清空写入后内存预览: " + insertMsgAddr.readPointer());
            taskIdGlobal = 0;
            receiverGlobal = "";
            senderGlobal = "";
            contentGlobal = "";
            atUserGlobal = "";
            sendMsgType = "";
            send({
                type: "finish",
                task_id: String(finishedTaskId),
                send_type: finishedSendType,
            })
        }
    });
}

setImmediate(attachReq2buf);

// -------------------------Req2Buf公共部分分区-------------------------

// -------------------------发送图片消息分区-------------------------

// 初始化进行内存的分配
function setupSendImgMessageDynamic() {

    // 1. 动态分配内存块（按需分配大小）
    // 分配原则：字符串给 64-128 字节，结构体按实际大小分配
    imgCgiAddr = Memory.alloc(128);
    sendImgMessageAddr = Memory.alloc(256);
    imgMessageAddr = Memory.alloc(256);
    uploadFunc1Addr = Memory.alloc(24);
    uploadFunc2Addr = Memory.alloc(24);
    uploadCallback = Memory.alloc(128);
    imageIdAddr = Memory.alloc(256);
    md5Addr = Memory.alloc(256);
    uploadAesKeyAddr = Memory.alloc(256);
    ImagePathAddr1 = Memory.alloc(256);
    uploadImageX1 = Memory.alloc(1024);
    imgProtoX1PayloadAddr = Memory.alloc(1024);

    // 图片数据写入
    patchString(imgCgiAddr, "/cgi-bin/micromsg-bin/uploadmsgimg");

    sendImgMessageAddr.add(0x00).writeU64(0);
    sendImgMessageAddr.add(0x08).writeU64(0);
    sendImgMessageAddr.add(0x10).writeU64(0);
    sendImgMessageAddr.add(0x18).writeU64(1);
    sendImgMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendImgMessageAddr.add(0x28).writePointer(imgMessageAddr);

    imgMessageAddr.add(0x00).writePointer(imgMessageCallbackFunc);
    imgMessageAddr.add(0x08).writeU32(taskIdGlobal);
    imgMessageAddr.add(0x0c).writeU32(0x6e);
    imgMessageAddr.add(0x10).writeU64(0x3);
    imgMessageAddr.add(0x18).writePointer(imgCgiAddr);
    imgMessageAddr.add(0x20).writeU64(0x22);
    imgMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    imgMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));

    patchImgProtobufFunc1Byte = patchImgProtobufFunc1.readByteArray(4);
    patchImgProtobufFunc2Byte = patchImgProtobufFunc2.readByteArray(4);
    imgProtobufDeleteAddrByte = imgProtobufDeleteAddr.readByteArray(4);

    // 视频数据写入
    videoCgiAddr = Memory.alloc(128);
    sendVideoMessageAddr = Memory.alloc(256);
    videoMessageAddr = Memory.alloc(256);
    videoIdAddr = Memory.alloc(256);
    videoPathAddr1 = Memory.alloc(256);
    uploadVideoX1 = Memory.alloc(1024);
    videoProtoX1PayloadAddr = Memory.alloc(2048);

    patchString(videoCgiAddr, "/cgi-bin/micromsg-bin/uploadvideo");

    sendVideoMessageAddr.add(0x00).writeU64(0);
    sendVideoMessageAddr.add(0x08).writeU64(0);
    sendVideoMessageAddr.add(0x10).writeU64(0);
    sendVideoMessageAddr.add(0x18).writeU64(1);
    sendVideoMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendVideoMessageAddr.add(0x28).writePointer(videoMessageAddr);

    videoMessageAddr.add(0x00).writePointer(videoMessageCallbackFunc);
    videoMessageAddr.add(0x08).writeU32(taskIdGlobal);
    videoMessageAddr.add(0x0c).writeU32(0x6e);
    videoMessageAddr.add(0x10).writeU64(0x3);
    videoMessageAddr.add(0x18).writePointer(videoCgiAddr);
    videoMessageAddr.add(0x20).writeU64(0x21);
    videoMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    videoMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));

    patchVideoProtobufFunc1Byte = patchVideoProtobufFunc1.readByteArray(4);
    patchVideoProtobufFunc2Byte = patchVideoProtobufFunc2.readByteArray(4);
    videoProtobufDeleteAddrByte = videoProtobufDeleteAddr.readByteArray(4);
}

setImmediate(setupSendImgMessageDynamic);


function patchImgProtoBuf() {
    Interceptor.attach(imageCallbackFuncAddr, {
        onEnter: function (args) {
            var firstValue = this.context.sp.add(0x10).readU32();
            console.log("[+] 捕获到 ImageCallbackFunc 调用，firstValue：", firstValue, "X1地址：", taskIdGlobal);
            if (firstValue === taskIdGlobal) {
                if (patchImgProtobufFunc1.readU32() !== 3573751839) {
                    Memory.patchCode(patchImgProtobufFunc1, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchImgProtobufFunc1});
                        cw.putNop();
                        cw.flush();
                    });
                    Memory.patchCode(patchImgProtobufFunc2, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchImgProtobufFunc2});
                        cw.putNop();
                        cw.flush();
                    });
                    Memory.patchCode(imgProtobufDeleteAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: imgProtobufDeleteAddr});
                        cw.putNop();
                        cw.flush();
                    });
                }
            } else {
                if (patchImgProtobufFunc1.readU32() === 3573751839) {
                    Memory.patchCode(patchImgProtobufFunc1, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchImgProtobufFunc1});
                        cw.putBytes(new Uint8Array(patchImgProtobufFunc1Byte));
                        cw.flush();
                    });
                    Memory.patchCode(patchImgProtobufFunc2, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchImgProtobufFunc2});
                        cw.putBytes(new Uint8Array(patchImgProtobufFunc2Byte));
                        cw.flush();
                    });
                    Memory.patchCode(imgProtobufDeleteAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: imgProtobufDeleteAddr});
                        cw.putBytes(new Uint8Array(imgProtobufDeleteAddrByte));
                        cw.flush();
                    });
                }

            }
        }
    })
}

setImmediate(patchImgProtoBuf);

function patchVideoProtoBuf() {
    Interceptor.attach(videoCallbackFuncAddr, {
        onEnter: function (args) {
            var firstValue = this.context.sp.add(0x10).readU32();
            console.log("[+] 捕获到 ImageCallbackFunc 调用，firstValue：", firstValue, "X1地址：", taskIdGlobal);
            if (firstValue === taskIdGlobal) {
                if (patchVideoProtobufFunc1.readU32() !== 3573751839) {
                    Memory.patchCode(patchVideoProtobufFunc1, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchVideoProtobufFunc1});
                        cw.putNop();
                        cw.flush();
                    });
                    Memory.patchCode(patchVideoProtobufFunc2, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchVideoProtobufFunc2});
                        cw.putNop();
                        cw.flush();
                    });
                    Memory.patchCode(videoProtobufDeleteAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: videoProtobufDeleteAddr});
                        cw.putNop();
                        cw.flush();
                    });
                }
            } else {
                if (patchVideoProtobufFunc1.readU32() === 3573751839) {
                    Memory.patchCode(patchVideoProtobufFunc1, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchVideoProtobufFunc1});
                        cw.putBytes(new Uint8Array(patchVideoProtobufFunc1Byte));
                        cw.flush();
                    });
                    Memory.patchCode(patchVideoProtobufFunc2, 4, code => {
                        const cw = new Arm64Writer(code, {pc: patchVideoProtobufFunc2});
                        cw.putBytes(new Uint8Array(patchVideoProtobufFunc2Byte));
                        cw.flush();
                    });
                    Memory.patchCode(videoProtobufDeleteAddr, 4, code => {
                        const cw = new Arm64Writer(code, {pc: videoProtobufDeleteAddr});
                        cw.putBytes(new Uint8Array(videoProtobufDeleteAddrByte));
                        cw.flush();
                    });
                }

            }
        }
    })
}

setImmediate(patchVideoProtoBuf);

function triggerSendImgMessage(taskId, sender, receiver) {
    if (!taskId || !receiver || !sender) {
        console.error("[!] taskId or receiver or sender is empty!");
        return "fail";
    }

    // 获取当前时间戳 (秒)
    const timestamp = Math.floor(Date.now() / 1000);
    lastSendTime = timestamp
    taskIdGlobal = taskId;
    receiverGlobal = receiver;
    senderGlobal = sender;

    imgMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendImgMessageAddr.add(0x20).writeU32(taskIdGlobal);

    const payloadData = [
        0x6e, 0x00, 0x00, 0x00,                         // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08
        0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // 0x10
        0x40, 0xec, 0x0e, 0x12, 0x01, 0x00, 0x00, 0x00, // 0x18
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20 cgi的长度
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x28
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // 0x38
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0x40
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA, // 0x48
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, // 0x50
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58
        0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D, // 0x68 default-
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B, // 0x70 longlink
        0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10, // 0x78
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA8
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xB0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xB8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x130
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x138
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x140
        0x01, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // 0x188
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
    ];
    triggerX1Payload.writeU32(taskIdGlobal);
    triggerX1Payload.add(0x04).writeByteArray(payloadData);
    triggerX1Payload.add(0x18).writePointer(imgCgiAddr);
    triggerX1Payload.add(0xb8).writePointer(triggerX1Payload.add(0xc0));
    triggerX1Payload.add(0x190).writePointer(triggerX1Payload.add(0x198));
    sendMsgType = "img"

    console.log("finished init image payload")
    const MMStartTask = new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);

    // 5. 调用函数
    try {
        return MMStartTask(triggerX0, triggerX1Payload);
    } catch (e) {
        console.error(`[!] Error trigger StartTask ${sendFuncAddr} with args: (${triggerX0}) (${triggerX1Payload}),   during execution: ` + e);
        return "fail";
    }
}

function triggerSendVideoMessage(taskId, sender, receiver) {
    console.log("[+] Manual Trigger Started...");
    if (!taskId || !receiver || !sender) {
        console.error("[!] taskId or receiver or sender is empty!");
        return "fail";
    }

    // 获取当前时间戳 (秒)
    const timestamp = Math.floor(Date.now() / 1000);
    lastSendTime = timestamp
    taskIdGlobal = taskId;
    receiverGlobal = receiver;
    senderGlobal = sender;

    videoMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendVideoMessageAddr.add(0x20).writeU32(taskIdGlobal);

    const payloadData = [
        0x6e, 0x00, 0x00, 0x00,                         // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08
        0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // 0x10
        0x40, 0xec, 0x0e, 0x12, 0x01, 0x00, 0x00, 0x00, // 0x18
        0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20 cgi的长度
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x28
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // 0x38
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0x40
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA, // 0x48
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, // 0x50
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58
        0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D, // 0x68 default-
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B, // 0x70 longlink
        0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10, // 0x78
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA8
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xB0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xB8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x130
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x138
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x140
        0x01, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // 0x188
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
    ];
    triggerX1Payload.writeU32(taskIdGlobal);
    triggerX1Payload.add(0x04).writeByteArray(payloadData);
    triggerX1Payload.add(0x18).writePointer(videoCgiAddr);
    triggerX1Payload.add(0xb8).writePointer(triggerX1Payload.add(0xc0));
    triggerX1Payload.add(0x190).writePointer(triggerX1Payload.add(0x198));
    sendMsgType = "video"

    console.log("finished init video payload")
    const MMStartTask = new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);

    // 5. 调用函数
    try {
        return MMStartTask(triggerX0, triggerX1Payload);
    } catch (e) {
        console.error(`[!] Error trigger StartTask ${sendFuncAddr} with args: (${triggerX0}) (${triggerX1Payload}),   during execution: ` + e);
        return "fail";
    }
}


// 拦截 Protobuf 编码逻辑，注入自定义 Payload
function attachProto() {
    Interceptor.attach(imgProtobufAddr, {
        onEnter: function (args) {
            var currTaskId = this.context.sp.add(0x30).readU32();
            if (currTaskId !== taskIdGlobal) {
                console.log(`[+] 拦截到非目标 currTaskId: ${currTaskId} taskIdGlobal: ${taskIdGlobal}`);
                return;
            }

            // 从图片队列获取上传信息
            const imgUploadInfo = getImageUploadInfo();
            let cdnKey = "";
            let aesKey = "";
            let md5Key = "";
            let targetId = "";

            if (imgUploadInfo) {
                cdnKey = imgUploadInfo.cdnKey;
                aesKey = imgUploadInfo.aesKey;
                md5Key = imgUploadInfo.md5Key;
                targetId = imgUploadInfo.targetId
            } else {
                console.error("[!] 无法获取图片上传信息")
                return
            }

            const type = [0x0A, 0x40, 0x0A, 0x01, 0x00]
            const msgId = [0x10].concat(generateRandom5ByteVarint())
            const cpHeader = [0x1A, 0x10]

            const randomId = [0x20, 0xAF, 0xAC, 0x90, 0x93, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
            const sysHeader = [0x2A, 0x15]
            // UnifiedPCMac 26 arm64
            const sys = [0x55, 0x6E, 0x69, 0x66, 0x69, 0x65, 0x64, 0x50, 0x43, 0x4D, 0x61, 0x63, 0x20, 0x32, 0x36, 0x20, 0x61, 0x72, 0x6D, 0x36, 0x34, 0x30]

            // 45872025384@chatroom_176787000_60_xwechat_1 只需要改这个时间戳就能重复发送
            const receiverMsgId = stringToHexArray(targetId).concat([0x5F])
                .concat(stringToHexArray(Math.floor(Date.now() / 1000).toString()))
                .concat([0x5F, 0x31, 0x36, 0x30, 0x5F, 0x78, 0x77, 0x65, 0x63, 0x68, 0x61, 0x74, 0x5F, 0x33]);

            // 0xb0, 0x02 是长度，需要看一下什么的长度
            const msgIdHeader = [0xb0, 0x02, 0x12, receiverMsgId.length + 2, 0x0A, receiverMsgId.length]

            const senderHeader = [0x1A, senderGlobal.length + 2, 0x0A, senderGlobal.length];
            // wxid_xxxx 或者 chatroom
            const sender = stringToHexArray(senderGlobal);
            const receiverHeader = [0x22, targetId.length + 2, 0x0A, targetId.length]
            // wxid_xxxx
            const receiver = stringToHexArray(targetId)
            const randomId1 = [0x28, 0xF4, 0x0B]
            const type1 = [0x30, 0x00]
            const randomId2 = [0x38, 0xF4, 0x0B]
            const randomId3 = [0x42, 0x04, 0x08, 0x00, 0x12, 0x00]
            const randomId4 = [0x48, 0x03]
            const htmlHeader = [0x52, 0x32];

            const html = [0x3C,
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, // 0x30 msgsour
                0x63, 0x65, 0x3E, 0x3C, 0x61, 0x6C, 0x6E, 0x6F, // 0x38 ce><alno
                0x64, 0x65, 0x3E, 0x3C, 0x66, 0x72, 0x3E, 0x31, // 0x40 de><fr>1
                0x3C, 0x2F, 0x66, 0x72, 0x3E, 0x3C, 0x2F, 0x61, // 0x48 </fr></a
                0x6C, 0x6E, 0x6F, 0x64, 0x65, 0x3E, 0x3C, 0x2F, // 0x50 lnode></
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, // 0x58 msgsour
                0x63, 0x65, 0x3E                          // 0x60 ce>
            ];

            const cdnHeader = [0x58, 0x01, 0x60, 0x02, 0x68, 0x00, 0x7A, 0xB2, 0x01]
            // 3057 开头的cdn key
            const cdn = stringToHexArray(cdnKey);

            const cdn2Header = [0x82, 0x01, 0xB2, 0x01]
            const cdn2 = stringToHexArray(cdnKey)

            const aesKeyHeader = [0x8A, 0x01, 0x20]
            const aesKeyBytes = stringToHexArray(aesKey)

            const randomId5 = [0x90, 0x01, 0x01, 0x98, 0x01, 0xFF, // 0x2C8
                0x13, 0xA0, 0x01, 0xFF, 0x13]

            const cdn3Header = [0xAA, 0x01, 0xB2, 0x01]
            const cdn3 = stringToHexArray(cdnKey)

            const randomId6 = [0xB0, 0x01, 0xF4, 0x0B]
            const randomId7 = [0xB8, 0x01, 0x68]
            const randomId8 = [0xC0, 0x01, 0x3A]
            const aesKey1Header = [0xCA, 0x01, 0x20]
            const aesKey1 = stringToHexArray(aesKey)
            const md5Header = [0xDA, 0x01, 0x20]
            const me5Key = stringToHexArray(md5Key)

            const randomId9 = [0xE0, 0x01, 0xd9, 0xe7, 0xc7, 0xF3, 0x02]

            var left0 = [
                0xF0, 0x01, 0x00, 0xA0, 0x02, 0x00, // 0x3E0
                0xC8, 0x02, 0x00, 0x00 // 0x3E8
            ]

            const finalPayload = type.concat(msgId, cpHeader, fileCp, randomId, sysHeader, sys, msgIdHeader, receiverMsgId,
                senderHeader, sender, receiverHeader, receiver, randomId1, type1, randomId2, randomId3, randomId4, htmlHeader, html,
                cdnHeader, cdn, cdn2Header, cdn2, aesKeyHeader, aesKeyBytes, randomId5, cdn3Header, cdn3, randomId6, randomId7, randomId8,
                aesKey1Header, aesKey1, md5Header, me5Key, randomId9, left0)

            imgProtoX1PayloadAddr.writeByteArray(finalPayload);
            console.log("[+] 图片 Payload 已写入，长度: " + finalPayload.length);

            this.context.x1 = imgProtoX1PayloadAddr;
            this.context.x2 = ptr(finalPayload.length);

            // console.log("[+] 图片 寄存器修改完成: X1=" + this.context.x1 + ", X2=" + this.context.x2, hexdump(imgProtoX1PayloadAddr, {
            //     offset: 0,
            //     length: 256,
            //     header: true,
            //     ansi: true
            // }));
        },
    });

    Interceptor.attach(videoProtobufAddr, {
        onEnter: function (args) {

            var currTaskId = this.context.sp.add(0x30).readU32();
            if (currTaskId !== taskIdGlobal) {
                console.log(`[+] 拦截到非目标 currTaskId: ${currTaskId} taskIdGlobal: ${taskIdGlobal}`);
                return;
            }

            // 从视频队列获取上传信息
            const videoUploadInfo = getVideoUploadInfo();
            let cdnKey = "";
            let aesKey = "";
            let md5Key = "";
            let videoId = "";
            let targetId = "";

            if (videoUploadInfo) {
                cdnKey = videoUploadInfo.cdnKey;
                aesKey = videoUploadInfo.aesKey;
                md5Key = videoUploadInfo.md5Key;
                videoId = videoUploadInfo.videoIdentity;
                targetId = videoUploadInfo.targetId;
            }  else {
                console.error("[!] 无法获取视频上传信息")
                return
            }

            const type = [0x0A, 0x3f, 0x0A, 0x01, 0x00]
            const msgId = [0x10].concat(generateRandom5ByteVarint())
            const cpHeader = [0x1A, 0x10]

            const randomId = [0x20, 0xAF, 0xAC, 0x90, 0x93, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
            const sysHeader = [0x2A, 0x15]
            // UnifiedPCMac 26 arm64
            const sys = [0x55, 0x6E, 0x69, 0x66, 0x69, 0x65, 0x64, 0x50, 0x43, 0x4D, 0x61, 0x63, 0x20, 0x32, 0x36, 0x20, 0x61, 0x72, 0x6D, 0x36, 0x34]

            // 注意：这里 sender 和 receiver 互换了
            const receiverMsgId = stringToHexArray(targetId).concat([0x5F])
                .concat(stringToHexArray(Math.floor(Date.now() / 1000).toString()))
                .concat([0x5F, 0x31, 0x36, 0x30, 0x5F, 0x78, 0x77, 0x65, 0x63, 0x68, 0x61, 0x74, 0x5F, 0x31]);

            // 0x81, 0x01 是 tag，0x12, 0x2b 是长度=43
            const msgIdHeader = [0x30, 0x76, 0x12, receiverMsgId.length]

            const senderHeader = [0x1A, senderGlobal.length];
            // sender 和 receiver 互换了，sender 是 wxid_ldftuhe36izg19
            const sender = stringToHexArray(senderGlobal);
            const receiverHeader = [0x22, targetId.length]
            // receiver 是 wxid_7wd1ece99f7i21
            const receiver = stringToHexArray(targetId)

            const randomId1 = [0x28, 0xac, 0x73, 0x30, 0xac, 0x73, 0x3a, 0x04, 0x08, 0x00, 0x12, 0x00]
            const type1 = [0x40, 0xe8, 0xf2, 0x6f]
            const randomId2 = [0x48, 0xe8, 0xf2, 0x6f]
            const randomId3 = [0x52, 0x04, 0x08, 0x00, 0x12, 0x00]
            const randomId4 = [0x58, 0x0d, 0x60, 0x01, 0x68, 0x02, 0x70, 0x00]
            const htmlHeader = [0x7a, 0x3c];

            const html = [0x3C, 0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65,
                0x3E, 0x3C, 0x61, 0x6C, 0x6E, 0x6F, 0x64, 0x65, 0x3E, 0x3C, 0x66, 0x72,
                0x3E, 0x31, 0x3C, 0x2F, 0x66, 0x72, 0x3E, 0x3C, 0x63, 0x66, 0x3E, 0x33,
                0x3C, 0x2F, 0x63, 0x66, 0x3E, 0x3C, 0x2F, 0x61, 0x6C, 0x6E, 0x6F, 0x64,
                0x65, 0x3E, 0x3C, 0x2F, 0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, 0x63,
                0x65, 0x3E]

            const cdnHeader = [0x82, 0x01, 0xb2, 0x01]
            // 3057 开头的cdn key
            const cdn = stringToHexArray(cdnKey);

            const aesKeyHeader = [0x8A, 0x01, 0x20]
            const aesKeyBytes = stringToHexArray(aesKey)

            const randomId5 = [0x90, 0x01, 0x01, 0x9A, 0x01, 0xB2, 0x01]

            const cdn2 = stringToHexArray(cdnKey)

            const randomId6 = [0xA0, 0x01, 0xAC, 0x73, 0xA8, 0x01, 0xE8, 0x02, 0xB0, 0x01, 0xCB, 0x01]

            const aesKey1Header = [0xBA, 0x01, 0x20]
            const aesKey1 = stringToHexArray(aesKey)
            const md5Header = [0xd2, 0x01, 0x20]
            const md5KeyBytes = stringToHexArray(md5Key)

            const md5Header1 = [0xAA, 0x02, 0x20]
            const md5Key1 = stringToHexArray(videoId)

            const randomId7 = [0xB0, 0x02, 0x00]

            const md5Key2Header = [0x82, 0x03, 0x20]
            const md5Key2 = stringToHexArray(md5Key)

            const cdn3Header = [0x8A, 0x03, 0xB2, 0x01]
            const cdn3 = stringToHexArray(cdnKey)

            const randomId8 = [0x92, 0x03, 0x20]

            const md5Key3 = stringToHexArray(aesKey)

            var left0 = [
                0x98, 0x03, 0xe8, 0xf2, 0x6f
            ]

            const finalPayload = type.concat(msgId, cpHeader, fileCp, randomId, sysHeader, sys, msgIdHeader, receiverMsgId,
                senderHeader, sender, receiverHeader, receiver, randomId1, type1, randomId2, randomId3, randomId4, htmlHeader, html,
                cdnHeader, cdn, aesKeyHeader, aesKeyBytes, randomId5, cdn2, randomId6, aesKey1Header, aesKey1, md5Header, md5KeyBytes, md5Header1,
                md5Key1, randomId7, md5Key2Header, md5Key2, cdn3Header, cdn3, randomId8, md5Key3, left0)

            videoProtoX1PayloadAddr.writeByteArray(finalPayload);
            console.log("[+] 视频Payload 已写入，长度: " + finalPayload.length);

            this.context.x1 = videoProtoX1PayloadAddr;
            this.context.x2 = ptr(finalPayload.length);

            // console.log("[+] 视频寄存器修改完成: X1=" + this.context.x1 + ", X2=" + this.context.x2, hexdump(videoProtoX1PayloadAddr, {
            //     offset: 0,
            //     length: finalPayload.length,
            //     header: true,
            //     ansi: true
            // }));
        },
    });
}

setImmediate(attachProto);


function triggerUploadImg(requestId, receiver, md5, imagePath) {
    uploadRequestIdGlobal = requestId;
    const payload = [
        0x20, 0x05, 0x33, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 函数 10802b8b0 的指针
        0x00, 0x05, 0x33, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 函数 107fd5908 的指针
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x40
        0xD0, 0x72, 0x20, 0x89, 0x0B, 0x00, 0x00, 0x00, // 图片id // 0x48
        0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x50
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x77, 0x78, 0x69, 0x64, 0x5F, 0x37, 0x77, 0x64, // 发送人 0x68
        0x31, 0x65, 0x63, 0x65, 0x39, 0x39, 0x66, 0x37,
        0x69, 0x32, 0x31, 0x00, 0x00, 0x00, 0x00, 0x13, // 发送人id长度
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xAA, 0xAA, 0xAA, 0x01, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xa0
        0xA0, 0xBE, 0x2D, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 0xa8
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb0
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0xb8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x55, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0xe0 图片地址 高清 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492_hd.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe8
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0xf0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x40, 0x54, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0x110 图片地址 普清 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x5D, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0x140 图片地址 缩略图 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492_thumb.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x148
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x188
        0x00, 0xAA, 0xAA, 0xAA, 0x01, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x1a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1a8
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x0A, 0x0A, // 0x1b0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1b8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1c0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1c8
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1d0
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1d8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1e0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1e8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1f0
        0xD0, 0x78, 0x46, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 0x1f8 某个key ecd57e9cf85f2e2087aee8c0fd1e445e
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x200
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x208
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x210
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x218
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x220
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x228
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x230
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x238
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x240
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x248
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x250
        0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x258
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x260
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x268
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x270
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x278
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x280
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 0x288
    ]

    patchString(imageIdAddr, receiver + "_" + String(Math.floor(Date.now() / 1000)) + "_" + Math.floor(Math.random() * 1001) + "_1");
    patchString(md5Addr, md5)
    patchString(uploadAesKeyAddr, generateAESKey())
    patchString(ImagePathAddr1, imagePath);

    uploadImageX1.writeByteArray(payload);
    uploadImageX1.writePointer(uploadFunc1Addr);
    uploadImageX1.add(0x08).writePointer(uploadFunc2Addr);
    uploadImageX1.add(0x48).writePointer(imageIdAddr);
    uploadImageX1.add(0x68).writeUtf8String(receiver);
    uploadImageX1.add(0xa8).writePointer(md5Addr);
    uploadImageX1.add(0xe0).writePointer(ImagePathAddr1);
    uploadImageX1.add(0x110).writePointer(ImagePathAddr1);
    uploadImageX1.add(0x140).writePointer(ImagePathAddr1);
    uploadImageX1.add(0x1f8).writePointer(uploadAesKeyAddr);

    const startUploadMedia = new NativeFunction(uploadImageAddr, 'int64', ['pointer', 'pointer']);

    console.log(`开始手动触发 C2C 上传 X0 ${uploadGlobalX0}, X1: ${uploadImageX1}`);
    return startUploadMedia(uploadGlobalX0, uploadImageX1);
}

function triggerUploadVideo(requestId, receiver, md5, videoPath) {
    uploadRequestIdGlobal = requestId;
    const payload = [
        0x20, 0x05, 0x33, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 函数 10802b8b0 的指针
        0x00, 0x05, 0x33, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 函数 107fd5908 的指针
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, // 0x40
        0xD0, 0x72, 0x20, 0x89, 0x0B, 0x00, 0x00, 0x00, // 图片id // 0x48
        0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x50
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x77, 0x78, 0x69, 0x64, 0x5F, 0x37, 0x77, 0x64, // 发送人 0x68
        0x31, 0x65, 0x63, 0x65, 0x39, 0x39, 0x66, 0x37,
        0x69, 0x32, 0x31, 0x00, 0x00, 0x00, 0x00, 0x13, // 发送人id长度
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xAA, 0xAA, 0xAA, 0x04, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xa0
        0xA0, 0xBE, 0x2D, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 0xa8
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb0
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0xb8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x55, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0xe0 图片地址 高清 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492_hd.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe8
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0xf0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x40, 0x54, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0x110 图片地址 普清 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x5D, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0x140 图片地址 缩略图 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492_thumb.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x148
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xE0, 0x03, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x188
        0x00, 0xAA, 0xAA, 0xAA, 0x01, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x1a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1a8
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x0A, 0x0A, // 0x1b0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1b8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1c0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1c8
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1d0
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1d8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1e0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1e8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1f0
        0xD0, 0x78, 0x46, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 0x1f8 某个key ecd57e9cf85f2e2087aee8c0fd1e445e
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x200
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x208
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x210
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x218
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x220
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x228
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x230
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x238
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x240
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x248
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x250
        0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x258
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x260
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x268
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x270
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x278
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x280
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x288
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x290
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x298
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2a8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2b0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2b8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2c0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2c8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2d0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2d8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2e0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 0x2e8
    ]

    patchString(videoIdAddr, receiver + "_" + String(Math.floor(Date.now() / 1000)) + "_" + Math.floor(Math.random() * 1001) + "_1");
    patchString(md5Addr, md5)
    patchString(uploadAesKeyAddr, generateAESKey())
    patchString(videoPathAddr1, videoPath);

    uploadVideoX1.writeByteArray(payload);
    uploadVideoX1.writePointer(uploadFunc1Addr);
    uploadVideoX1.add(0x08).writePointer(uploadFunc2Addr);
    uploadVideoX1.add(0x48).writePointer(videoIdAddr);
    uploadVideoX1.add(0x68).writeUtf8String(receiver);
    uploadVideoX1.add(0xa8).writePointer(md5Addr);
    uploadVideoX1.add(0xe0).writePointer(videoPathAddr1);
    uploadVideoX1.add(0x110).writePointer(videoPathAddr1);
    uploadVideoX1.add(0x140).writePointer(videoPathAddr1);
    uploadVideoX1.add(0x1f8).writePointer(uploadAesKeyAddr);

    const startUploadMedia = new NativeFunction(uploadImageAddr, 'int64', ['pointer', 'pointer']);

    return startUploadMedia(uploadGlobalX0, uploadVideoX1);
}

function attachUploadMedia() {
    Interceptor.attach(uploadImageAddr.add(0x10), {
        onEnter: function (args) {
            try {
                uploadGlobalX0 = this.context.x0;
                const selfId = this.context.x1.add(0x68).readUtf8String();
                const filePath = this.context.x1.add(0xe0).readPointer().readUtf8String();
                send({
                    type: "upload",
                    self_id: selfId,
                })
                console.log("UploadMedia x0: " + uploadGlobalX0 + " filePath: " + filePath + " selfId: " + selfId);
            } catch (e) {
                console.log("[-] attachUploadMedia error: " + e);
                uploadGlobalX0 = this.context.x0;
            }
        }
    })
}

setImmediate(attachUploadMedia);


function patchCdnOnComplete() {
    Interceptor.attach(cndOnCompleteAddr, {
        onEnter: function (args) {

            try {
                const x2 = this.context.x2;
                const currentFileId = x2.add(0x20).readPointer().readUtf8String();
                const imageFileId = imageIdAddr.readUtf8String();
                const videoFileId = videoIdAddr.readUtf8String();
                if (currentFileId !== imageFileId && currentFileId !== videoFileId) {
                    console.log("[-] CndOnComplete x2: " + x2 + " currentFileId: " + currentFileId +
                        " imageFileId: " + imageFileId + " videoFileId:" + videoFileId);
                    return;
                }

                const cdnKey = x2.add(0x60).readPointer().readUtf8String();
                const aesKey = x2.add(0x78).readPointer().readUtf8String();
                const md5Key = x2.add(0x90).readPointer().readUtf8String();
                const videoId = x2.add(0xf0).readPointer().readUtf8String();
                const targetId = x2.add(0x40).readUtf8String();

                console.log("X2: " + x2 + "[+] cdnKey: " + cdnKey + " aesKey: " + aesKey +
                    " md5Key: " + md5Key + " videoId:" + videoId);

                if (cdnKey !== "" && cdnKey != null && aesKey !== "" && aesKey != null &&
                    md5Key !== "" && md5Key != null) {

                    // 判断是图片还是视频，存入对应队列
                    if (videoId !== null && videoId !== "") {
                        // 视频
                        pushVideoUploadInfo({
                            cdnKey: cdnKey,
                            aesKey: aesKey,
                            md5Key: md5Key,
                            videoIdentity: videoId,
                            targetId: targetId
                        });
                        send({
                            type: "upload_video_finish",
                            request_id: uploadRequestIdGlobal,
                            target_id: targetId,
                            cdn_key: cdnKey,
                            aes_key: aesKey,
                            md5_key: md5Key
                        });
                        uploadRequestIdGlobal = "";
                    } else {
                        // 图片
                        pushImageUploadInfo({
                            cdnKey: cdnKey,
                            aesKey: aesKey,
                            md5Key: md5Key,
                            targetId: targetId
                        });
                        send({
                            type: "upload_image_finish",
                            request_id: uploadRequestIdGlobal,
                            target_id: targetId,
                            cdn_key: cdnKey,
                            aes_key: aesKey,
                            md5_key: md5Key
                        });
                        uploadRequestIdGlobal = "";
                    }
                } else {
                    console.error("cdnKey or aesKey or md5key 为空");
                    send({
                        type: "upload_failed",
                        request_id: uploadRequestIdGlobal,
                        target_id: targetId,
                        message: "cdnKey or aesKey or md5key 为空"
                    });
                    uploadRequestIdGlobal = "";
                }
            } catch (e) {
                console.log("[-] Memory access error at onEnter: " + e);
                send({
                    type: "upload_failed",
                    request_id: uploadRequestIdGlobal,
                    message: String(e)
                });
                uploadRequestIdGlobal = "";
            }
        }
    });
}

setImmediate(patchCdnOnComplete)

function attachGetCallbackFromWrapper() {
    Interceptor.attach(uploadGetCallbackWrapperAddr, {
        onEnter: function (args) {
            try {
                const tmpFileId = this.context.x1.readPointer().readUtf8String();
                const imageFileId = imageIdAddr.readUtf8String();
                const videoFileId = videoIdAddr.readUtf8String()
                if (tmpFileId !== imageFileId && tmpFileId !== videoFileId) {
                    console.log("[+] GetCallbackFromWrapper tmpFileId: " + tmpFileId + " imageFileId: " + imageFileId + " videoFileId:" + videoFileId);
                    return
                }

                uploadCallback.add(0x10).writePointer(uploadGetCallbackWrapperFuncAddr);
                this.context.x8 = uploadCallback;
                console.log("[+] GetCallbackFromWrapper x8: " + this.context.x8);
            } catch (e) {
                console.log("[-] GetCallbackFromWrapper error: " + e);
            }
        }
    })

    Interceptor.attach(uploadOnCompleteAddr, {
        onEnter: function (args) {
            try {
                const tmpFileId = this.context.x1.readPointer().readUtf8String();
                const imageFileId = imageIdAddr.readUtf8String();
                const videoFileId = videoIdAddr.readUtf8String()
                if (tmpFileId !== imageFileId && tmpFileId !== videoFileId) {
                    console.log("[+] OnComplete tmpFileId: " + tmpFileId + " imageFileId: " + imageFileId + " videoFileId:" + videoFileId);
                    return
                }

                uploadCallback.add(0x30).writePointer(uploadOnCompleteFuncAddr);
                this.context.x8 = uploadCallback;
                console.log("[+] OnComplete x8: " + this.context.x8);
            } catch (e) {
                console.log("[-] OnComplete error: " + e);
            }
        }
    })
}

setImmediate(attachGetCallbackFromWrapper);

rpc.exports = {
    triggerSendImgMessage: triggerSendImgMessage,
    triggerUploadImg: triggerUploadImg,
    triggerSendTextMessage: triggerSendTextMessage,
    triggerDownload: triggerDownload,
    triggerUploadVideo: triggerUploadVideo,
    triggerSendVideoMessage: triggerSendVideoMessage,
};

// -------------------------发送图片消息分区-------------------------

// -------------------------接收消息分区-------------------------
function setupDownloadFileDynamic() {
    downloadFileX1 = Memory.alloc(1624)
    fileIdAddr = Memory.alloc(128)
    fileMd5Addr = Memory.alloc(128)
    downloadAesKeyAddr = Memory.alloc(128)
    filePathAddr = Memory.alloc(256)
    fileCdnUrlAddr = Memory.alloc(256)

}

setImmediate(setupDownloadFileDynamic)

function setReceiver() {
    Interceptor.attach(buf2RespAddr, {
        onEnter: function (args) {
            const currentPtr = this.context.x20;
            if (currentPtr.add(0).readU8() !== 0x08) {
                return
            }

            const x2 = this.context.x0.toInt32();
            // console.log(" [+] currentPtr: ", hexdump(currentPtr, {
            //     offset: 0,
            //     length: x2,
            //     header: true,
            //     ansi: true
            // }));
            const fields = getProtobufRawBytes(currentPtr, x2)

            const sender = fields[0]
            const receiver = fields[1]
            const content = fields[2]
            const mediaContent = fields[3]
            const xml = fields[4]
            const userContent = fields[5]
            const msgId = protobufVarintToNumberString(fields[6])

            if (typeof sender !== "string" || sender === "" || typeof receiver !== "string" || receiver === "" ||
                typeof content !== "string" || content === "" || typeof msgId !== "string" || msgId === "") {
                return;
            }

            var selfId = receiver
            var msgType = "private"
            var groupId = ""
            var senderUser = sender
            var senderNickname = ""
            var messages = getMessages(content, sender, mediaContent);

            if (sender.includes("@chatroom")) {
                msgType = "group"
                groupId = sender

                let splitIndex = content.indexOf(':')
                const sendUserStart = content.indexOf('wxid_')
                senderUser = content.substring(sendUserStart, splitIndex).trim();

                const atUserMatch = xml.match(/<atuserlist>([\s\S]*?)<\/atuserlist>/);
                const atUser = atUserMatch ? atUserMatch[1] : null;
                if (atUser) {
                    atUser.split(',').forEach(atUser => {
                        atUser = atUser.trim();
                        if (atUser) {
                            messages.push({type: "at", data: {qq: atUser}});
                        }
                    });
                }

                // 处理用户的名称
                splitIndex = userContent?.indexOf(':')
                if (splitIndex === -1) {
                    splitIndex = userContent?.indexOf('在群聊中@了你') !== -1 ? userContent?.indexOf('在群聊中@了你') : userContent?.indexOf('在群聊中发了一段语')
                    senderNickname = userContent?.substring(0, splitIndex).trim();
                } else {
                    senderNickname = userContent?.substring(0, splitIndex).trim();
                }
                if (!senderNickname) {
                    senderNickname = senderUser
                }

            } else {
                // 处理用户的名称
                const splitIndex = userContent?.indexOf(':')
                senderNickname = userContent?.substring(0, splitIndex).trim();
                if (!senderNickname) {
                    senderNickname = senderUser
                }
            }

            send({
                time: Date.now(),
                post_type: "message",
                message_type: msgType,
                user_id: senderUser, // 发送人的 ID
                self_id: selfId, // 接收人的 ID
                group_id: groupId, // 群 ID
                message_id: msgId,
                type: "send",
                raw: {peerUid: msgId},
                message: messages,
                sender: {user_id: senderUser, nickname: senderNickname},
                msgsource: xml,
                raw_message: content,
                show_content: userContent
            })
        },
    });

    Interceptor.attach(startDownloadMedia, {
        onEnter: function (args) {
            downloadGlobalX0 = this.context.x0;
            var fileIDAddr = this.context.x1.add(0x40).readPointer();
            var fileId = fileIDAddr?.readUtf8String();
            const t = this.context.x1.add(0xA0).readU32()
            console.log(" [+] download file: ", fileId, " type", t);
            if (t === 3) {
                if (fileId.endsWith("_1")) {
                    this.context.x1.add(0xA0).writeU32(0x02);
                }
                if (fileId.endsWith("_31")) {
                    this.context.x1.add(0xA0).writeU32(0x04);
                }
            }
        }
    })

    Interceptor.attach(downloadFileAddr, {
        onEnter: function (args) {
            var dataPtr = this.context.x22;
            var dataLen = this.context.x20.toInt32();
            var fileId = this.context.sp.add(0x30).readPointer().readUtf8String();
            var cdnUrl = this.context.x19.add(0x2F8).readPointer().readUtf8String();

            if (dataLen > 0) {
                var buffer = dataPtr.readByteArray(dataLen);
                var uint8Array = new Uint8Array(buffer);

                send({
                    type: "download",
                    media: Array.from(uint8Array),
                    file_id: fileId,
                    cdn_url: cdnUrl,
                })
            }
        }
    });

    Interceptor.attach(downloadImagAddr, {
        onEnter: function (args) {
            var dataPtr = this.context.x22;
            var dataLen = this.context.x2.toInt32();
            var fileId = this.context.x19.add(0x2E0).readPointer().readUtf8String();
            var cdnUrl = this.context.x19.add(0x2F8).readPointer().readUtf8String();

            if (dataLen > 0) {
                var buffer = dataPtr.readByteArray(dataLen);
                var uint8Array = new Uint8Array(buffer);

                send({
                    type: "download",
                    media: Array.from(uint8Array),
                    file_id: fileId,
                    cdn_url: cdnUrl,
                })
            }
        }
    });

    Interceptor.attach(downloadVideoAddr, {
        onEnter: function (args) {
            var dataPtr = this.context.x1;
            var dataLen = this.context.x24.toInt32();
            var fileId = this.context.x22.add(0x40).readPointer().readUtf8String();
            var cdnUrl = this.context.x22.add(0x58).readPointer().readUtf8String();

            if (dataLen > 0) {
                var buffer = dataPtr.readByteArray(dataLen);
                var uint8Array = new Uint8Array(buffer);

                send({
                    type: "download",
                    media: Array.from(uint8Array),
                    file_id: fileId,
                    cdn_url: cdnUrl,
                })
            }
        }
    });
}

setImmediate(setReceiver)

// fileType:  HdImage => 1,Image => 2, thumbImage => 3, Video => 4, File => 5,
function triggerDownload(receiver, cdnUrl, aesKey, filePath, fileType) {
    const downloadMediaPayload = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF0, 0xB6, 0x4C, 0xFC, 0x0A, 0x00, 0x00, 0x00, // 0x40
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x80, 0x10, 0x4B, 0xFA, 0x0A, 0x00, 0x00, 0x00, // 0x58
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0xF0, 0xB3, 0x4C, 0xFC, 0x0A, 0x00, 0x00, 0x00, // 0x70
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x60, 0xC4, 0x2D, 0xFE, 0x0A, 0x00, 0x00, 0x00, // 0x88
        0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x98
        0x03, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0xa0
        0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, // 0xa8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xc0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xd0
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xd8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x11, 0x28, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0xAA, 0xAA, 0xAA, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1E, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x1a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x22, 0x1A, 0xFE, 0x0A, 0x00, 0x00, 0x00, // 0x1d0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1f0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x200
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x288
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x298
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x4F, 0x56, 0xFC, 0x0A, 0x00, 0x00, 0x00, // 0x2c0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x300
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x318
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x340
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x378
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0x00, // 0x3e0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    patchString(fileIdAddr, receiver + "_" + String(Math.floor(Date.now() / 1000)) + "_" + Math.floor(Math.random() * 1001) + "_1");
    patchString(fileCdnUrlAddr, cdnUrl)
    patchString(downloadAesKeyAddr, aesKey)
    patchString(filePathAddr, filePath);

    downloadFileX1.writeByteArray(downloadMediaPayload);
    downloadFileX1.add(0x40).writePointer(fileIdAddr);
    downloadFileX1.add(0x58).writePointer(fileCdnUrlAddr);
    downloadFileX1.add(0x70).writePointer(downloadAesKeyAddr);
    downloadFileX1.add(0x88).writePointer(filePathAddr);
    downloadFileX1.add(0xa0).writeU32(fileType);

    const startDwMedia = new NativeFunction(startDownloadMedia, 'int64', ['pointer', 'pointer']);
    return startDwMedia(downloadGlobalX0, downloadFileX1);
}

function getMessages(content, sender, mediaContent) {
    var messages = [];
    if (sender.includes("@chatroom")) {
        let splitIndex = content.indexOf(':')
        let pureContent = content.substring(splitIndex + 1).trim();
        const parts = pureContent.split('\u2005');
        for (let part of parts) {
            part = part.trim();
            if (part.startsWith("<?xml version=\"1.0\"?><msg><img")) {
                messages.push({type: "image", data: {text: part}});
            } else if (part.startsWith("<msg><voicemsg")) {
                messages.push({type: "record", data: {text: part}});
            } else if (part.startsWith("<?xml version=\"1.0\"?><msg><appmsg")) {
                const regex = /<type>(.*?)<\/type>/s;
                const match = part.match(regex);
                if (match.length > 1) {
                    switch (match[1]) {
                        case "5":
                            messages.push({type: "share", data: {text: part}});
                            break
                        case "6":
                            messages.push({type: "file", data: {text: part}});
                            break
                    }
                }
            } else if (part.startsWith("<msg><emoji")) {
                messages.push({type: "face", data: {text: part}});
            } else if (part.startsWith("<?xml version=\"1.0\"?><msg><videomsg")) {
                messages.push({type: "video", data: {text: part}});
            } else if (part.startsWith("<sysmsg") || part.startsWith("<?xml version=\"1.0\"?><sysmsg")) {
                messages.push({type: "sys", data: {text: part}});
            } else {
                messages.push({type: "text", data: {text: part}});
            }
        }
    } else {
        if (content.startsWith("<?xml version=\"1.0\"?><msg><img")) {
            messages.push({type: "image", data: {text: content}});
        } else if (content.startsWith("<msg><voicemsg")) {
            const audioStart = mediaContent.indexOf(2);
            if (audioStart !== -1) {
                mediaContent = mediaContent.subarray(audioStart);
            }
            messages.push({type: "record", data: {text: content, media: Array.from(mediaContent)}});
        } else if (content.startsWith("<?xml version=\"1.0\"?><msg><appmsg")) {
            const regex = /<type>(.*?)<\/type>/s;
            const match = content.match(regex);
            if (match.length > 1) {
                switch (match[1]) {
                    case "5":
                        messages.push({type: "share", data: {text: content}});
                        break
                    case "6":
                        messages.push({type: "file", data: {text: content}});
                        break
                }
            }
        } else if (content.startsWith("<msg><emoji")) {
            messages.push({type: "face", data: {text: content}});
        } else if (content.startsWith("<?xml version=\"1.0\"?><msg><videomsg")) {
            messages.push({type: "video", data: {text: content}});
        } else if (content.startsWith("<sysmsg") || content.startsWith("<?xml version=\"1.0\"?><sysmsg")) {
            messages.push({type: "sys", data: {text: content}});
        } else {
            messages.push({type: "text", data: {text: content}});
        }
    }

    return messages;
}

// -------------------------接收消息分区-------------------------
