var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}

var buf2RespAddr = baseAddr.add(0x3721FA0)
var downloadImagAddr = baseAddr.add(0x4A084EC)

// -------------------------接收消息分区-------------------------
function setReceiver() {
    Interceptor.attach(buf2RespAddr, {
        onEnter: function (args) {
            const currentPtr = this.context.x1;
            let start = 0x1e;
            let senderLen = currentPtr.add(start).readU8();
            if (senderLen !== 0x14 && senderLen !== 0x13) {
                start = 0x1d;
                let senderLen = currentPtr.add(start).readU8();
                if (senderLen !== 0x14 && senderLen !== 0x13) {
                    return
                }
            }

            const x2 = this.context.x2.toInt32();
            console.log(" [+] currentPtr: ", hexdump(currentPtr, {
                offset: 0,
                length: x2,
                header: true,
                ansi: true
            }));
            const fields = getProtobufRawBytes(currentPtr, x2)

            const sender = fields[0]
            const receiver = fields[1]
            const content = fields[2]
            const mediaContent = fields[3]
            const xml = fields[4]
            const userContent = fields[5]
            const msgId = protobufVarintToNumberString(fields[6])

            if (sender === "" || receiver === "" || content === "" || msgId === "") {
                console.log("字段缺失，无法解析 sender:" + sender + " receiver:" + receiver + hexdump(currentPtr, {
                    length: x2,
                    header: true,
                    ansi: true,
                }))
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

    Interceptor.attach(downloadImagAddr, { // 建议使用函数起始地址或你计算出的偏移地址
        onEnter: function (args) {
            var dataPtr = this.context.x1;
            var dataLen = this.context.x2.toInt32();
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
}


// 使用 setImmediate 确保在模块加载后执行
setImmediate(setReceiver)

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
        } else {
            messages.push({type: "text", data: {text: content}});
        }
    }

    return messages;
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

                while (i < uint8Array.length) {
                    let b = uint8Array[i];
                    length |= (b & 0x7F) << shift;
                    bytesReadForLen++;
                    i++;
                    if (!(b & 0x80)) break;
                    shift += 7;
                }

                // 2. 截取原始 Byte 数据
                if (i + length <= uint8Array.length) {
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

    for (let i = 0; i < uint8Array.length; i++) {
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


// -----------------------测试函数-------------------------

function testGetProtobufRawBytes() {
    const rawMemoryData = [
        0x08, 0x00, 0x12, 0xdc, 0x0f, 0x08, 0x01, 0x12, 0xd7, 0x0f, 0x08, 0x05, 0x12, 0xd2, 0x0f, 0x08,
        0xcc, 0x0f, 0x12, 0xcc, 0x0f, 0x08, 0x85, 0xa0, 0xd5, 0xe8, 0x04, 0x12, 0x15, 0x0a, 0x13, 0x77,
        0x78, 0x69, 0x64, 0x5f, 0x37, 0x77, 0x64, 0x31, 0x65, 0x63, 0x65, 0x39, 0x39, 0x66, 0x37, 0x69,
        0x32, 0x31, 0x1a, 0x15, 0x0a, 0x13, 0x77, 0x78, 0x69, 0x64, 0x5f, 0x6c, 0x64, 0x66, 0x74, 0x75,
        0x68, 0x65, 0x33, 0x36, 0x69, 0x7a, 0x67, 0x31, 0x39, 0x20, 0x22, 0x2a, 0xe6, 0x03, 0x0a, 0xe3,
        0x03, 0x3c, 0x6d, 0x73, 0x67, 0x3e, 0x3c, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x6d, 0x73, 0x67, 0x20,
        0x65, 0x6e, 0x64, 0x66, 0x6c, 0x61, 0x67, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x63, 0x61, 0x6e, 0x63,
        0x65, 0x6c, 0x66, 0x6c, 0x61, 0x67, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x66, 0x6f, 0x72, 0x77, 0x61,
        0x72, 0x64, 0x66, 0x6c, 0x61, 0x67, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x76, 0x6f, 0x69, 0x63, 0x65,
        0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x76, 0x6f, 0x69, 0x63, 0x65,
        0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x31, 0x31, 0x30, 0x30, 0x22, 0x20, 0x6c, 0x65,
        0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x31, 0x32, 0x35, 0x32, 0x22, 0x20, 0x62, 0x75, 0x66, 0x69,
        0x64, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x61, 0x65, 0x73, 0x6b, 0x65, 0x79, 0x3d, 0x22, 0x37, 0x30,
        0x66, 0x34, 0x31, 0x36, 0x37, 0x36, 0x63, 0x38, 0x31, 0x31, 0x34, 0x33, 0x62, 0x66, 0x33, 0x61,
        0x38, 0x38, 0x36, 0x62, 0x33, 0x33, 0x38, 0x32, 0x33, 0x30, 0x62, 0x37, 0x38, 0x37, 0x22, 0x20,
        0x76, 0x6f, 0x69, 0x63, 0x65, 0x75, 0x72, 0x6c, 0x3d, 0x22, 0x33, 0x30, 0x35, 0x32, 0x30, 0x32,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x34, 0x34, 0x62, 0x33, 0x30, 0x34, 0x39, 0x30, 0x32, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x32, 0x30, 0x34, 0x66, 0x36, 0x35, 0x63, 0x39, 0x63, 0x65, 0x30, 0x30, 0x32,
        0x30, 0x33, 0x32, 0x66, 0x38, 0x30, 0x32, 0x39, 0x30, 0x32, 0x30, 0x34, 0x32, 0x35, 0x66, 0x38,
        0x33, 0x64, 0x62, 0x37, 0x30, 0x32, 0x30, 0x34, 0x36, 0x39, 0x61, 0x31, 0x33, 0x38, 0x65, 0x30,
        0x30, 0x34, 0x32, 0x34, 0x33, 0x38, 0x36, 0x31, 0x36, 0x34, 0x36, 0x33, 0x33, 0x35, 0x33, 0x36,
        0x36, 0x36, 0x33, 0x33, 0x32, 0x64, 0x33, 0x37, 0x33, 0x30, 0x33, 0x33, 0x36, 0x36, 0x32, 0x64,
        0x33, 0x34, 0x36, 0x36, 0x36, 0x36, 0x33, 0x30, 0x32, 0x64, 0x33, 0x39, 0x33, 0x38, 0x33, 0x36,
        0x36, 0x34, 0x32, 0x64, 0x33, 0x30, 0x36, 0x32, 0x33, 0x33, 0x36, 0x32, 0x36, 0x32, 0x36, 0x32,
        0x36, 0x32, 0x33, 0x31, 0x33, 0x32, 0x33, 0x38, 0x33, 0x38, 0x33, 0x37, 0x30, 0x32, 0x30, 0x34,
        0x30, 0x31, 0x31, 0x38, 0x30, 0x30, 0x30, 0x66, 0x30, 0x32, 0x30, 0x31, 0x30, 0x30, 0x30, 0x34,
        0x30, 0x30, 0x39, 0x61, 0x38, 0x35, 0x33, 0x65, 0x64, 0x61, 0x22, 0x20, 0x76, 0x6f, 0x69, 0x63,
        0x65, 0x6d, 0x64, 0x35, 0x3d, 0x22, 0x22, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x6d, 0x73,
        0x67, 0x69, 0x64, 0x3d, 0x22, 0x34, 0x39, 0x37, 0x35, 0x30, 0x66, 0x31, 0x61, 0x35, 0x31, 0x35,
        0x61, 0x37, 0x64, 0x30, 0x35, 0x35, 0x63, 0x35, 0x66, 0x31, 0x38, 0x34, 0x32, 0x64, 0x32, 0x66,
        0x66, 0x39, 0x37, 0x34, 0x30, 0x77, 0x78, 0x69, 0x64, 0x5f, 0x6c, 0x64, 0x66, 0x74, 0x75, 0x68,
        0x65, 0x33, 0x36, 0x69, 0x7a, 0x67, 0x31, 0x39, 0x5f, 0x32, 0x33, 0x36, 0x5f, 0x31, 0x37, 0x37,
        0x32, 0x31, 0x37, 0x33, 0x35, 0x33, 0x35, 0x22, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x75, 0x73, 0x65,
        0x72, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x77, 0x78, 0x69, 0x64, 0x5f, 0x37, 0x77, 0x64, 0x31,
        0x65, 0x63, 0x65, 0x39, 0x39, 0x66, 0x37, 0x69, 0x32, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f,
        0x6d, 0x73, 0x67, 0x3e, 0x30, 0x03, 0x38, 0x01, 0x42, 0xea, 0x09, 0x08, 0xe4, 0x09, 0x12, 0xe4
    ];

    const pBuffer = {
        // 模拟指针读取内存返回 ArrayBuffer
        readByteArray: function (size) {
            // 返回模拟数据的 ArrayBuffer 副本
            const slice = rawMemoryData.slice(0, size);
            const ab = new ArrayBuffer(slice.length);
            const view = new Uint8Array(ab);
            for (let i = 0; i < slice.length; i++) view[i] = slice[i];
            return ab;
        }
    };

    const results = getProtobufRawBytes(pBuffer, rawMemoryData.length);
    console.log(results);
}
