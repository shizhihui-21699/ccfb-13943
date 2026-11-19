# SCP/1 协议规范 v1.0

> 本文档是 SCP/1 的**规范性**描述。检验工具（`scp-probe`）只依据本文档判断实现
> 是否合规，不读取任何实现源码。文中每条规定都有稳定编号 `R-x.y`，
> 检验工具的报告与测试用例按编号引用。
>
> 关键词 **必须 / 不得 / 应** 按 RFC 2119 理解。

SCP/1 用于内部服务之间的双向加密信道，提供：基于 X25519 的密钥协商、ChaCha20-Poly1305
记录层、票据式断线恢复（session ticket）、以及在线密钥轮换（rekey）。

---

## 1. 传输与分帧

**R-1.1** 连接建立后双方按帧交换消息。帧格式：

```
+----------------+-----------+------------------+
| body_len: u32  | type: u8  | body: body_len-1 |
+----------------+-----------+------------------+
```

`body_len` 为大端序，计数范围为 `type` 字节加 `body`，因此最小合法帧为 5 字节。
`body_len` 最大为 16384（含 type 字节）。

**R-1.2** 若某帧的 `body_len` 大于 16384，或 `body_len` 为 0，接收方**必须**发送
`ERR(TooLarge)` 或 `ERR(DecodeError)` 并关闭连接。

**R-1.3** 若帧的 `type` 不属于下表，接收方**必须**发送 `ERR(DecodeError)` 并关闭连接。

**R-1.4** 每个消息类型只允许由固定的一方发送。收到由自己一方发送的类型
（"反射"）**必须**按 `ERR(DecodeError)` 处理并关闭连接。

| type | 名称 | 允许方向 | 明文/密文 |
|------|------|----------|-----------|
| 0x01 | `CLIENT_HELLO` | C→S | 明文 |
| 0x02 | `SERVER_HELLO` | S→C | 明文 |
| 0x03 | `CLIENT_FINISH` | C→S | 明文 |
| 0x04 | `SERVER_FINISH` | S→C | 明文 |
| 0x10 | `APP_DATA` | 双向 | 密文 |
| 0x20 | `REKEY` | C→S 发起，S→C 应答 | 密文 |
| 0x30 | `CLOSE` | 双向 | 密文 |
| 0x40 | `SESSION_RESUME` | C→S | 明文 |
| 0x41 | `RESUME_OK` | S→C | 明文 |
| 0x7f | `ERR` | S→C | 明文 |

**R-1.5** 服务端**不得**在收到 `CLOSE` 之后继续处理任何业务消息。

## 2. 消息格式

**R-2.1** 所有多字节整数为大端序。字段长度固定，解析后必须**恰好**消耗完 `body`，
多余或缺失字节按 `ERR(DecodeError)` 处理。

```
CLIENT_HELLO   : version:u16 | random:[u8;32] | eph_pub:[u8;32]           (66 B)
SERVER_HELLO   : version:u16 | random:[u8;32] | eph_pub:[u8;32]
                 | suite:u16 | ticket_ttl_ms:u32                            (72 B)
CLIENT_FINISH  : verify:[u8;32]                                            (32 B)
SERVER_FINISH  : verify:[u8;32] | ticket:[u8;72]                           (104 B)
APP_DATA       : seq:u64 | ciphertext                                     (≥ 8+16 B)
REKEY          : seq:u64 | ciphertext                                     (≥ 8+32+16 B)
CLOSE          : seq:u64 | ciphertext                                     (8+16 B)
SESSION_RESUME : ticket:[u8;72] | random:[u8;32] | eph_pub:[u8;32]         (136 B)
RESUME_OK      : random:[u8;32] | eph_pub:[u8;32] | ticket:[u8;72]         (136 B)
ERR            : code:u16                                                   (2 B)
```

`version` 当前为 `1`。`suite` 当前为 `1`（X25519 + HKDF-SHA256 + ChaCha20-Poly1305）。

## 3. 握手

**R-3.1** 服务端在连接上的**第一条**消息**必须**是 `CLIENT_HELLO` 或 `SESSION_RESUME`。
任何其他首帧**必须**以 `ERR(UnexpectedMessage)` 关闭。

**R-3.2** 服务端收到 `CLIENT_HELLO` 后：校验 `version`，不为 1 时**必须**以
`ERR(BadVersion)` 关闭；生成自己的 `random` 与临时 X25519 公钥，发送
`SERVER_HELLO`，进入 `AwaitFinish` 状态。

**R-3.3** 服务端**不得**在未收到 `CLIENT_HELLO` 时发送 `SERVER_HELLO`，
亦不得在未收到 `SERVER_HELLO` 后接受 `CLIENT_FINISH`。

**R-3.4** `CLIENT_FINISH.verify` 必须等于规范 §3.5 定义的 `client_verify`。
不相等时**必须**以 `ERR(BadMac)` 关闭，且**不得**发送 `SERVER_FINISH`。

**R-3.5** 密钥编排（所有 `HKDF` 均为 HKDF-SHA256，`HMAC` 为 HMAC-SHA256）：

```
th_hello      = SHA256( len(CH.body) || CH.body || len(SH.body) || SH.body )
prk_hs        = HKDF(salt = th_hello, ikm = X25519(e_c, e_s), info = "SCP1 hs")
c_hs          = HKDF(salt = prk_hs, ikm = "", info = "c hs")
s_hs          = HKDF(salt = prk_hs, ikm = "", info = "s hs")
client_verify = HMAC(key = c_hs, msg = "client verify")
server_verify = HMAC(key = s_hs, msg = "server verify")
master        = HKDF(salt = prk_hs, ikm = client_verify || server_verify, info = "SCP1 master")
psk           = HKDF(salt = master,  ikm = "", info = "resume psk")
prk_app       = HKDF(salt = th_hello, ikm = master, info = "app")
c2s_key       = HKDF(salt = prk_app, ikm = "", info = "c2s")
s2c_key       = HKDF(salt = prk_app, ikm = "", info = "s2c")
```

**R-3.6** 服务端在收到合法 `CLIENT_FINISH` 后**必须**发送 `SERVER_FINISH`
（`verify = server_verify`，附新签发票据），然后进入 `Established` 状态。

> **R-3.7（关键顺序规则）** 应用数据密钥只从 `th_hello` 推导，因此**客户端在
> 发出 `CLIENT_FINISH` 之前就已经持有一切必要密钥**。尽管如此：
>
> - 服务端在进入 `Established`（即已发送 `SERVER_FINISH`）之前，收到
>   `APP_DATA`、`REKEY` 或 `CLOSE` **必须**以 `ERR(UnexpectedMessage)` 关闭，
>   **不得**解密、处理或应答这些消息。
> - 这条规则是本协议唯一的"禁止 0-RTT"约束。实现若在完成握手前处理业务数据，
>   即构成与 §R-3.7 不符的严重违例。

**R-3.8** 已建立连接上再次收到 `CLIENT_HELLO`、`CLIENT_FINISH`、`SERVER_HELLO`
或 `SERVER_FINISH`，**必须**以 `ERR(UnexpectedMessage)` 关闭。

## 4. 记录层

**R-4.1** `APP_DATA`/`REKEY`/`CLOSE` 的 `seq` 字段为该方向、该密钥纪元（epoch）内
从 0 开始严格递增的计数器。每方向独立计数。

**R-4.2** `nonce = epoch:u32 || seq:u64`（共 12 字节），`AAD = type:u8`，
密钥为本方向当前纪元密钥。解密失败**必须**以 `ERR(BadMac)` 关闭。

**R-4.3** 接收方**必须**校验 `seq` **恰好**等于期望值（上一成功帧 + 1，纪元内首帧为 0）。
`seq` 小于期望值（重放）或大于期望值（跳号）**必须**以 `ERR(Replay)` 关闭，且
**不得**把明文交给应用层。

**R-4.4** `APP_DATA` 明文语义：`op:u8 || body`。

- `op = 0x01`（PING）：服务端**必须**在同纪元内以 `APP_DATA` 应答
  `op = 0x81`（PONG），`body` 原样返回。
- `op = 0x02`（SUBMIT）：`body` 任意；服务端把该连接的提交计数器加一并
  **必须**以 `APP_DATA` 应答 `op = 0x82`（ACK），`body = counter:u32`（大端）。
  每个被接受的 `SUBMIT` **必须**恰好使计数器加一。
- 其他 `op`：服务端**必须**以 `APP_DATA` 应答 `op = 0xff`、`body = [0x01]`。

服务端应答的 `seq` 使用服务端方向的计数器。

**R-4.5** `CLOSE` 明文为空。收到 `CLOSE` 后服务端**必须**以空明文 `CLOSE` 应答，
然后关闭连接；此后**不得**再发送任何帧。

## 5. 密钥轮换（Rekey）

**R-5.1** 仅允许客户端发起 `REKEY`。服务端收到合法 `REKEY` 时必须：

1. 用当前接收纪元密钥解密，明文为 32 字节 `contribution_c`；
2. 按 **R-5.2** 推导新纪元密钥并**立即**切换（epoch += 1，两方向 `seq` 归零）；
3. 在新纪元下发送 `REKEY` 应答，明文为 32 字节 `contribution_s`
   （服务端随机生成），`seq = 0`。

**R-5.2** 轮换推导（`c2s`/`s2c` 为当前纪元两方向密钥）：

```
prk_rekey  = HKDF(salt = "SCP1 rekey", ikm = c2s || s2c || contribution_c, info = "")
c2s_next   = HKDF(salt = prk_rekey, ikm = "", info = "send")
s2c_next   = HKDF(salt = prk_rekey, ikm = "", info = "recv")
```

**R-5.3** 服务端**不得**在 `Established` 之前处理 `REKEY`（见 R-3.7）。

**R-5.4** 轮换后，用**旧纪元**密钥封装的任何帧都**必须**以 `ERR(BadMac)` 关闭
（旧密钥已不可用于解密）。反之，服务端**不得**以旧纪元密钥发送应答。

## 6. 断线恢复（Session Ticket）

**R-6.1** `SERVER_FINISH.ticket` 与 `RESUME_OK.ticket` 中各字段对客户端不透明，客户端
**必须**原样保存。票据格式：`id:[u8;16] | expiry_ms:u64 | sealed:[u8;48]`，
其中 `sealed` 是只有服务端能解开的 AEAD 密文，内含 `psk`。`expiry_ms` 为
签发时的绝对毫秒时间戳。

**R-6.2** `SESSION_RESUME` **只能**作为连接首帧（同 R-3.1）。服务端在
`Established` 等状态收到时**必须**以 `ERR(UnexpectedMessage)` 关闭。

**R-6.3** 服务端**必须**校验票据：格式正确、`sealed` 可解且认证通过、
`expiry_ms` 未过期。任一失败**必须**以 `ERR(TicketInvalid)` 关闭，且**不得**
发送 `RESUME_OK`。

**R-6.4** 票据**单次使用**。成功恢复后该票据**必须**作废；同一票据第二次用于
`SESSION_RESUME` **必须**以 `ERR(TicketInvalid)` 关闭。

**R-6.5** 恢复成功时服务端发送 `RESUME_OK`（新 `random`、新临时公钥、新票据），
随即进入 `Established`。恢复的密钥编排：

```
th_resume = SHA256( len(ticket)||ticket || len(cr)||cr || len(sr)||sr
                    || len(e_c)||e_c || len(e_s)||e_s )
prk_r     = HKDF(salt = th_resume, ikm = psk || X25519(e_c, e_s), info = "SCP1 resume")
c2s       = HKDF(salt = prk_r, ikm = "", info = "c2s app")
s2c       = HKDF(salt = prk_r, ikm = "", info = "s2c app")
```

恢复后 epoch = 0，两方向 `seq` 从 0 开始。**不**需要 `CLIENT_FINISH`。

## 7. 超时与异常

**R-7.1** 自 TCP 建立起，若握手（`CLIENT_HELLO` → `SERVER_FINISH`）未在
**400 ms** 内完成，服务端**必须**发送 `ERR(DeadlineExceeded)` 并关闭。

**R-7.2** `Established` 连接若在 **1500 ms** 内没有任何入站帧，服务端**应**在
1500–3000 ms 内静默关闭连接（不发 `ERR`）。

**R-7.3** 任何协议错误都**必须**以 `ERR(code)` 结束，且发送 `ERR` 后**必须**关闭
连接；`ERR` 之后不得再发送任何帧。

**R-7.4** 服务端**不得**因任意输入而 panic 或泄漏其它连接的状态。

## 8. 合规等级

- **严重违例**：接受了规范禁止的消息顺序（R-3.7、R-4.3、R-5.4、R-6.4 等），
  即"不该被接受的消息顺序被接受"。
- **功能偏差**：拒绝或无法完成规范要求的行为（R-4.4、R-6.5 等），影响互通。
- **健壮性偏差**：超时、超长帧、反射帧等异常输入的处理与规范不符。
