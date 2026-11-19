# SCP/1 black-box report — `lenient`

160 interaction(s) in 3 round(s), 21.8s. Stop reason: **coverage saturated: 2 consecutive round(s) added no new behaviour after 3 round(s) and 160 interaction(s)**.
55 distinct (phase, action, behaviour) observations.

## Verdict

**2 critical, 0 major, 2 minor** divergence(s).

### 1. APP_DATA(retired key epoch) in Established [after-activity] (minor)

- **id**: `lenient:R-4.2:Established/app-data-old-epoch`
- **rule**: R-4.2
- **phase**: Established
- **connection context**: after-activity
- **expected**: reject with ERR(BadMac)
- **observed**: SILENCE
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server failed to end the connection after a record it could not authenticate (a retired-epoch record). Ignoring an authentication failure is itself a fault (R-4.2/R-7.3), even though the key rotation requirement (R-5.4) was met.

Reproduction:
```
connect to the target (Established)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket
send REKEY(seq=0, contribution C0); read REKEY(seq=0) in epoch 1
keep the epoch-0 keys as the 'retired' set
send APP_DATA(seq=expected, ct=SEAL(epoch-0 key, op=0x01 'ping'))
expected: reject with ERR(BadMac)
```

Last frame sent (hex):

```
0000001e100000000000000001624941774ba4327b7b004f47f72d993b0f1f37820b
```

### 2. APP_DATA(corrupted tag, seq = expected) in Established [quiet] (minor)

- **id**: `lenient:R-4.2:Established/app-data-bad-mac`
- **rule**: R-4.2
- **phase**: Established
- **connection context**: quiet
- **expected**: reject with ERR(BadMac)
- **observed**: SILENCE
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server did not answer ERR(BadMac) and close after a record failed authentication; it ignored the frame and kept the connection open (R-4.2/R-7.3).

Reproduction:
```
connect to the target (Established)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket
flip one bit in the AEAD tag of an otherwise valid APP_DATA
expected: reject with ERR(BadMac)
```

Last frame sent (hex):

```
0000001e1000000000000000000502aad3ca82cb67bc122100b38bf9843d2d95548d
```

### 3. APP_DATA(seq = expected + 1) in Established [after-activity] (critical)

- **id**: `lenient:R-4.3:Established/app-data-gap`
- **rule**: R-4.3
- **phase**: Established
- **connection context**: after-activity
- **expected**: reject with ERR(Replay)
- **observed**: APP_DATA(8170696e67)
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server accepted a record whose seq did not equal the expected value; out-of-order and duplicated records are therefore both accepted (R-4.3).

Reproduction:
```
connect to the target (Established)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket
send APP_DATA(seq=expected+1, ct=SEAL(...))
expected: reject with ERR(Replay)
```

Last frame sent (hex):

```
0000001e100000000000000002f9b4b616d426bb10195cb940b072d0c2065ebb752c
```

### 4. APP_DATA(seq = expected - 1) in Established [after-activity] (critical)

- **id**: `lenient:R-4.3:Established/app-data-replay`
- **rule**: R-4.3
- **phase**: Established
- **connection context**: after-activity
- **expected**: reject with ERR(Replay)
- **observed**: APP_DATA(8170696e67)
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server accepted a record whose seq did not equal the expected value; out-of-order and duplicated records are therefore both accepted (R-4.3).

Reproduction:
```
connect to the target (Established)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket
send APP_DATA(seq=expected-1, ct=SEAL(...))
expected: reject with ERR(Replay)
```

Last frame sent (hex):

```
0000001e1000000000000000014d213149602220948ee7211bc5b0ef45cc85aad949
```

