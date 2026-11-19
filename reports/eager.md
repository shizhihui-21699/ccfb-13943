# SCP/1 black-box report — `eager`

154 interaction(s) in 3 round(s), 15.7s. Stop reason: **coverage saturated: 2 consecutive round(s) added no new behaviour after 3 round(s) and 154 interaction(s)**.
55 distinct (phase, action, behaviour) observations.

## Verdict

**4 critical, 0 major, 0 minor** divergence(s).

### 1. APP_DATA(seq = expected) in AwaitFinish [quiet] (critical)

- **id**: `eager:R-3.7:AwaitFinish/app-data`
- **rule**: R-3.7
- **phase**: AwaitFinish
- **connection context**: quiet
- **expected**: reject with ERR(UnexpectedMessage)
- **observed**: APP_DATA(8170696e67)
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server processed application-layer ciphertext before the handshake finished. The epoch-0 keys are derivable from the HELLO flight alone (R-3.5), so early records decrypt; the state machine is the only thing that keeps 0-RTT data out (R-3.7), and it does not here.

Reproduction:
```
connect to the target (AwaitFinish)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
derive epoch-0 keys from SHA256(HELLO flight) (spec R-3.5)
send APP_DATA(seq=expected, ct=SEAL(key, op=0x01 'ping'))
expected: reject with ERR(UnexpectedMessage)
```

Last frame sent (hex):

```
0000001e1000000000000000009111defd7eb3ed9d4760e00a42b8ee106a7f0c8cbc
```

### 2. APP_DATA(seq = expected + 1) in AwaitFinish [quiet] (critical)

- **id**: `eager:R-3.7:AwaitFinish/app-data-gap`
- **rule**: R-3.7
- **phase**: AwaitFinish
- **connection context**: quiet
- **expected**: reject with ERR(UnexpectedMessage)
- **observed**: APP_DATA(8170696e67)
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server processed application-layer ciphertext before the handshake finished. The epoch-0 keys are derivable from the HELLO flight alone (R-3.5), so early records decrypt; the state machine is the only thing that keeps 0-RTT data out (R-3.7), and it does not here.

Reproduction:
```
connect to the target (AwaitFinish)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
derive epoch-0 keys from SHA256(HELLO flight) (spec R-3.5)
send APP_DATA(seq=expected+1, ct=SEAL(...))
expected: reject with ERR(UnexpectedMessage)
```

Last frame sent (hex):

```
0000001e100000000000000001c6a3eecff99aef3b3f9be5effdaaf7a39a299ef7e5
```

### 3. REKEY(valid) in AwaitFinish [quiet] (critical)

- **id**: `eager:R-3.7:AwaitFinish/rekey`
- **rule**: R-3.7
- **phase**: AwaitFinish
- **connection context**: quiet
- **expected**: reject with ERR(UnexpectedMessage)
- **observed**: REKEY(old_epoch=false)
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server performed a key rotation before SERVER_FINISH. Keys in use do not match the handshake transcript it has not yet completed (R-3.7/R-5.3).

Reproduction:
```
connect to the target (AwaitFinish)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
derive epoch-0 keys from SHA256(HELLO flight) (spec R-3.5)
send REKEY(seq=expected, ct=SEAL(key, C1))
expected: reject with ERR(UnexpectedMessage)
```

Last frame sent (hex):

```
00000039200000000000000000778e48a431af276f18fb04be562f6051a88365f6be1d848e728fe9865e81af53c7aa866ca72385fd9557a7cc3da73d66
```

### 4. CLOSE(valid) in AwaitFinish [quiet] (critical)

- **id**: `eager:R-3.7:AwaitFinish/close`
- **rule**: R-3.7
- **phase**: AwaitFinish
- **connection context**: quiet
- **expected**: reject with ERR(UnexpectedMessage)
- **observed**: CLOSE
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server honoured a CLOSE it received before the handshake finished (R-3.7).

Reproduction:
```
connect to the target (AwaitFinish)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
derive epoch-0 keys from SHA256(HELLO flight) (spec R-3.5)
send CLOSE(seq=expected, ct=SEAL(key, ''))
expected: reject with ERR(UnexpectedMessage)
```

Last frame sent (hex):

```
000000193000000000000000003d39d751145d70ce25fa9c1e01247d5e
```

