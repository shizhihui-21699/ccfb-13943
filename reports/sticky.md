# SCP/1 black-box report — `sticky`

160 interaction(s) in 3 round(s), 21.0s. Stop reason: **coverage saturated: 2 consecutive round(s) added no new behaviour after 3 round(s) and 160 interaction(s)**.
55 distinct (phase, action, behaviour) observations.

## Verdict

**4 critical, 0 major, 0 minor** divergence(s).

### 1. APP_DATA(retired key epoch) in Established [after-activity] (critical)

- **id**: `sticky:R-5.4:Established/app-data-old-epoch`
- **rule**: R-5.4
- **phase**: Established
- **connection context**: after-activity
- **expected**: reject with ERR(BadMac)
- **observed**: APP_DATA(8170696e67)
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server accepted a record sealed under a key epoch it had already rotated away from; retired keys are not destroyed (R-5.4).

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

### 2. SESSION_RESUME(valid ticket) in Established [after-activity] (critical)

- **id**: `sticky:R-6.2:Established/resume`
- **rule**: R-6.2
- **phase**: Established
- **connection context**: after-activity
- **expected**: reject with ERR(UnexpectedMessage)
- **observed**: RESUME_OK
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server honoured SESSION_RESUME outside a connection's first frame (R-6.2).

Reproduction:
```
connect to the target (Established)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket
send SESSION_RESUME(ticket=valid, random=Rr, eph=Er)
expected: reject with ERR(UnexpectedMessage)
```

Last frame sent (hex):

```
0000008940536002fb8f3a2a75a7098aa51c8538bb000001a1f5052380a9656a220672dc1aa31efd86522488f0ebbe57c6e44e80386f6b6666d37522e5adbda15d3f84c84b7713453be7fa3cd4423fda2c36d3a9ca256d3ad1aff6fabfe7853283a3244efcb9f442564ffffddf13d69f8fd92e863a70f27c9a7cb253a46cc88a14cfde53aa954b98cdacec2415
```

### 3. SESSION_RESUME(reused ticket) in Established [after-activity] (critical)

- **id**: `sticky:R-6.2:Established/resume-reused-ticket`
- **rule**: R-6.2
- **phase**: Established
- **connection context**: after-activity
- **expected**: reject with ERR(UnexpectedMessage)
- **observed**: RESUME_OK
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server accepted a session ticket that had already been redeemed once (R-6.4).

Reproduction:
```
connect to the target (Established)
send CLIENT_HELLO(version=1, random=Rc, eph=Ec)
read SERVER_HELLO(version=1, random=Rs, eph=Es)
send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket
first redeem the ticket on a throwaway connection
send SESSION_RESUME(same ticket again)
expected: reject with ERR(UnexpectedMessage)
```

Last frame sent (hex):

```
00000089400c2cd8acecbf66be29d34262df07b72b000001a1f50526a9d0fa0f54fc06003480085891eb951b7d5cd5c68ff4f57d4f6412f34a609945e84235c29a82ff1b3513073a0923b5ff53c5009e5c873ff1c076bac3b6baa5980fc1f7b5636bff4382f905941dfed7bb23d30128ce758bba648fc328eda767a4571c3e938bdaae73bcae52d2aa771fea3a
```

### 4. SESSION_RESUME(reused ticket) in Start [quiet] (critical)

- **id**: `sticky:R-6.4:Start/resume-reused-ticket`
- **rule**: R-6.4
- **phase**: Start
- **connection context**: quiet
- **expected**: reject with ERR(TicketInvalid)
- **observed**: RESUME_OK
- **reproduced in**: 2/2 repetitions
- **why it matters**: Server accepted a session ticket that had already been redeemed once (R-6.4).

Reproduction:
```
connect to the target (Start)
first redeem the ticket on a throwaway connection
send SESSION_RESUME(same ticket again)
expected: reject with ERR(TicketInvalid)
```

Last frame sent (hex):

```
000000894023db4669163efe53d256df8a68102d81000001a1f504f1bd0739e54eee91113186ea6aa5e72935f9674588544bdafabdd7c233b34c2a3e08a39409cdfce6d273875b3cc061a9cd9d49e871d2e18b477afc38b55c126293402bf0298dfb42a8564c8a12e4596cfd2176aa6790bb367dd0adccd2fc9f46a68a9eac057aea01229a5791c7008470963a
```

