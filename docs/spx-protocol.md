# SPX 协议契约(agent ↔ server)

SPX(Sliver eXchange)是自定义 agent↔server 线协议。本文档是 **agent 侧实现必须遵守的契约**,与 Go server 实现(`D:/sliver/server/c2/spx.go` / `spx_dispatch.go` / `spx_registry.go`)逐字节对齐。

- 传输:TLS/TCP(server 认证;**MinVersion 1.2**,1.3 可用时协商 1.3)
- 线格式:JSON 控制头 + 裸字节 payload
- 身份:Ed25519 challenge-response AUTH(公钥白名单在 server 配置)

## 1. 帧格式(全部大端)

```
[0:4]   magic   0x53315854  "S1XT"
[4]     version 0x01
[5]     flags   0x01=compressed 0x02=close 0x04=stream-cont(当前恒 0)
[6:10]  header 长度 u32(≤64 KiB)
[10:14] payload 长度 u32(≤256 MiB)
[14:]   JSON header,然后 raw payload
```

## 2. JSON 控制头

字段名即 `SpxHeader` 的 `[JsonPropertyName]`(single-letter):

| 字段 | 类型 | 说明 |
|---|---|---|
| `v` | int | 协议版本 = 1 |
| `t` | string | 消息类型(下表) |
| `i` | string | 消息 ID(16 hex) |
| `r` | string | 响应时回填请求方 `i` |
| `c` | uint32 | opcode |
| `s` | string | session/beacon id(注册后) |
| `ts` | int64 | epoch 毫秒 |
| `f` | int | 0x01=session 模式 0x02=beacon 模式 |
| `m` | json | REG 元数据 / AUTH 回复 `{pubkey,sig}` |
| `k` | string | 流/通道 key(tunnel/socks) |
| `e` | string | ERR 错误串 |
| `msg` | string | CMD/RES:sliverpb 消息类型名 |
| `body` | json | CMD/RES:消息的 protojson 体 |

## 3. 消息类型(`t`)

```
AUTH AUTH_OK REG REG_OK CMD RES TASK TASK_RES PING PONG OPEN DATA CLOSE ERR
```

## 4. Opcode(`c`)

```
0x0001 register    0x0002 ping      0x0003 close
0x0100 cmd         0x0101 result
0x0200 task        0x0201 task_res
0x0300 open        0x0301 data      0x0302 close_ch
0x0400 event
```

## 5. AUTH 握手(Ed25519 challenge-response)

1. server 发 `{t:"AUTH", i, body:"<base64 nonce>"}`
2. agent 回 `{t:"AUTH", i, r:<挑战i>, m:{"pubkey":"<hex pub>","sig":"<base64 ed25519.Sign(nonce)>"}}`
3. server 回 `{t:"AUTH_OK", r}` 或 `{t:"ERR", e:"auth failed"}`

> 公钥必须已在 server 配置 `spx[].authorized_keys` 中(hex 小写;server 按字节比较,大小写无关)。

## 6. REG(注册)

### Session 模式(`f:0x01`)
`m` 元数据字段(镜像 `sliverpb.Register`,protojson lowerCamelCase):

```
name hostname uuid username uid gid os arch pid filename
activeC2 version reconnectInterval proxyUrl locale configId peerId capabilities
```

server 回 `{t:"REG_OK", r, s:"<session-id>", c:0x0001}`。

### Beacon 模式(`f:0x02`,`s`=beaconID)
`m` 额外字段:`interval jitter nextCheckin`。server 回 `REG_OK` 带 `s`=beaconID。

## 7. PING / PONG

agent **不主动发** PING；服务器发 `{t:"PING", i, c:0x0002}` → agent 回 `{t:"PONG", r:<i>, c:0x0002}`。

## 8. CMD / RES(命令往返)

- server → agent:`{t:"CMD", i, c:0x0100, msg:"<类型名>", body:{protojson}}`
- agent → server:`{t:"RES", r:<CMD 的 i>, c:0x0101, msg:"<响应类型名>", body:{protojson}}`

`msg` 注册表(server `spxMsgConstructors`)，**agent 已实现**的命令加 ✅，其余为 server 注册但 agent 有意不实现：

| 请求 msg | 响应 msg | 命令 | agent |
|---|---|---|---|
| `Ping` | `Ping` | 探活 | ✅ |
| `LsReq` | `Ls` | 列目录 | ✅ |
| `CdReq` | —(空) | 切换目录 | ✅ |
| `PwdReq` | `Pwd` | 当前路径 | ✅ |
| `DownloadReq` | `Download` | 下载文件 | ✅ |
| `UploadReq` | `Upload` | 上传文件 | ✅ |
| `ExecuteReq` | `Execute` | 执行程序 | ❌（走程序集 JIT 替代） |
| `PsReq` | `Ps` | 进程列表 | ❌ |
| `ShellReq` | —(走 OPEN/DATA) | 交互 shell | ❌ |
| `KillReq` | —(空) | 结束会话 | ✅ |

> 通用消息字段:`request { async timeout beaconId sessionId }` 内嵌于各请求,`response { err async }` 内嵌于各响应(protojson lowerCamelCase,可省略)。

### 命令字段级定义(protojson lowerCamelCase)

**Ping**:`nonce int32`

**LsReq / Ls**
```
LsReq: path string
Ls:  path string, exists bool,
     files[ { name,isDir,size,modTime,timezone?... mode,link,uid,gid } ],
     timezone string, timezoneOffset int32
```
目录项(`FileInfo`):`name isDir size modTime(epoch秒) mode link uid gid`——NTFS 无 uid/gid,留空。

**CdReq / PwdReq / Pwd**
```
CdReq: path string       (仅改 agent cwd 状态,无响应体)
PwdReq: {}               → Pwd: path string
```

**DownloadReq / Download**
```
DownloadReq: path string, start int64, stop int64, recurse bool,
             maxBytes int64, maxLines int64, restrictedToFile bool
Download:  path string, encoder string, exists bool, start int64, stop int64,
           data bytes(protojson 中 base64), isDir bool,
           readFiles int32, unreadableFiles int32
```
- `start/stop` 区间读取(0/0=全文件);`recurse` 目录递归;`maxBytes/maxLines` 截断。

**UploadReq / Upload**
```
UploadReq: path string, encoder string, data bytes(base64), isIoc bool,
           fileName string, isDirectory bool, overwrite bool
Upload:    path string, writtenFiles int32, unwriteableFiles int32
```

**ExecuteReq / Execute**
```
ExecuteReq: path string, args[], output bool, stdout string, stderr string,
            envInheritance bool, env{string:string}, background bool, ppid uint32
Execute:    status uint32, stdout bytes(base64), stderr bytes(base64), pid uint32
```

**PsReq / Ps**
```
PsReq: fullInfo bool
Ps:    processes[ { pid,ppid,executable,owner,architecture,sessionId,cmdLine[] } ]
```

**KillReq**:`force bool`(仅结束会话)

## 9. Beacon TASK / TASK_RES

- check-in:agent 发 `{t:"TASK", s:beaconID, c:0x0200}` → server 回一个或多个 `{t:"TASK", i, c:0x0200, msg, body}`
- 结果回传:agent 发 `{t:"TASK_RES", r:<task 的 i>, s:beaconID, c:0x0201, msg, body}`
- 无响应命令（如 `CdReq`）:agent 仍回 `{t:"TASK_RES", msg:"CdReq", body:{}}` 标记任务完成
- 批次结束:server 不发终止帧，agent 用 5 秒无帧超时判断批次结束，然后断开连接睡眠

## 10. 流式通道(OPEN/DATA/CLOSE)

- server → agent:`{t:"OPEN", k:"<channel>", c:0x0300}`(会话/转发建立)
- 数据:agent ↔ server `{t:"DATA", k:"<tunnelID>", c:0x0301}`,payload = **原始字节**
- 关闭:`{t:"CLOSE", k:"<tunnelID>", c:0x0302}`

## 11. 错误

任何未识别消息 → server 回 `{t:"ERR", r, e:"unknown message type"}`。

## 12. server 侧配置

```yaml
spx:
  - host: "0.0.0.0"
    port: 9999
    authorized_keys:
      - "<agent hex ed25519 pubkey>"
```
