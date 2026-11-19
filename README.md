# SCP/1 black-box conformance prober

A test bench for a hand-rolled encrypted session protocol with a handshake,
key re-negotiation, and ticket-based resumption. It exists because of a real
class of incident: *a server accepted business data that arrived before the
handshake finished*, because its state machine never checked.

The bench answers three questions, **without reading the implementation's
source**:

1. What protocol orderings does this implementation actually accept?
2. Where does that differ from the written specification?
3. How do I reproduce each difference, exactly?

Everything here is ordinary TCP plus the spec's own crypto. The prober has
no privileged access: no source, no logs, no debug hooks, no shared memory —
only messages on a socket.

## Layout

| path | what it is |
|------|------------|
| `docs/spec.md` | The normative SCP/1 spec, with stable rule ids `R-x.y`. This is the only oracle. |
| `crates/scp-core` | The non-secret half of the protocol: framing, message shapes, key schedule, AEAD records, tickets. Shared by targets *and* prober, exactly as a public spec would be. |
| `crates/scp-target` | Four server implementations: one compliant `reference`, and three with distinct planted faults. |
| `crates/scp-probe` | The prober. A scriptable client, an executable model of the spec, a search engine, and a report writer. |

## The four targets

Each target is a complete SCP/1 server. They are **deliberately** different
in the way real implementations drift:

| impl | what is wrong | rule(s) | why this is realistic |
|------|---------------|---------|-----------------------|
| `reference` | nothing | — | The oracle. Must always come back clean. |
| `eager` | processes `APP_DATA` / `REKEY` / `CLOSE` **before** the handshake completes | R-3.7 | The original incident. Since app keys are derivable from the HELLO flight (TLS-1.3-style 0-RTT), only the state machine keeps early data out. |
| `lenient` | does not check receive `seq` (replays work), and ignores records that fail to authenticate instead of closing | R-4.3, R-4.2 | The "works in integration, breaks behind a proxy" profile. |
| `sticky` | tickets are reusable, retired key epochs still decrypt, `SESSION_RESUME` is honoured mid-session | R-6.4, R-5.4, R-6.2 | The "session layer bolted on later" profile. |

The fault catalogue is code (`Impl::expected_faults`), and the self-tests
assert that the black-box prober finds **exactly** those rules and nothing
else — for the reference, that means nothing at all.

## How the prober works

**1. Reach a phase.** A fresh TCP connection is walked into one of
`Start`, `AwaitFinish`, `Established`, or `Closed`, using the protocol
honestly (or, for `Closed`, by closing it and then poking the dead socket).

**2. Present one input.** One of 19 abstract actions: a legal hello, a bad
version, a bad-MAC finish, a valid/forged/reused ticket, in-sequence and
out-of-sequence records, an old-epoch record, a corrupted-tag record, a
rekey, a close, malformed wire bytes, a reflected server frame, or silence.

**3. Observe everything.** Reads until the target goes quiet or closes and
classifies each reply (`APP_DATA`, `ERR(code)`, `RESUME_OK`, close-after-ERR,
bare close, silence, unparseable bytes). A record that only authenticates
under the *previous* epoch is tagged as such.

**4. Diff against the model.** `model.rs` is the spec rendered as a
`(phase, action) -> Expect` table. A divergence is ranked:

* **critical** — something the spec says must be rejected was accepted
  (the incident class),
* **major** — something legal was rejected (interop breakage),
* **minor** — right direction, wrong error code or wrong close behaviour.

**5. Emit a finding** with the rule id, expected vs observed, the exact bytes
last sent, and a step-by-step reproduction script. `scp-probe --replay-phase
… --replay-action …` re-runs that exact case.

### Handling timeouts, randomness and hidden state

* **Timeouts** are real but bounded. Every reply wait is short; the two idle
  tests wait past the spec's own deadlines (400 ms handshake, 1500 ms idle).
  A late-but-present close is never treated as critical.
* **Randomness** (fresh ephemerals, fresh tickets) is handled by
  **repetition**: every case runs `--reps` times with independent seeds. A
  divergence is a finding only if it reproduces in *every* repetition that
  reached the phase. A flaky one is recorded as *intermittent* and never
  reported as a verdict.
* **Hidden state** is handled by a second search stage: the
  state-sensitive actions are re-run on a connection that has **already
  carried a legal request/response round-trip**, so a server whose answer
  depends on what came before is observed in both conditions.

### The stopping rule

Stated up front and enforced:

> **Stop when `--patience` (default 2) consecutive rounds add no new
> coverage, or when the interaction budget is exhausted.**

Coverage is the set of `(phase, action, behavioural class)` triples, so
reaching a phase by another route but seeing the same answer is *not*
progress. The rounds are: the full frontier, the hidden-state expansion, then
a **confirmation round** that re-runs every divergent or inconsistent case.
A deterministic target therefore converges after the confirmation round; a
target with real nondeterminism keeps producing new behaviour and gets more
budget spent on it. The stop reason is printed in every report.

## Running it

```sh
# build
cargo build --release

# terminal 1: start a target (prints ADDR=127.0.0.1:PORT)
./target/release/scp-target --impl eager

# terminal 2: probe it
./target/release/scp-probe --addr 127.0.0.1:PORT --name eager \
    --out reports/eager.md --json reports/eager.json

# replay one finding
./target/release/scp-probe --addr 127.0.0.1:PORT \
    --replay-phase AwaitFinish --replay-action app-data
```

Or sweep every implementation at once (each as its own process, probed over
real TCP) and write a report per target:

```sh
BUDGET=450 ./scripts/run_all.sh
```

### Self-tests

```sh
cargo test
```

The meaningful ones live in `crates/scp-probe/tests/self_test.rs`:

* `reference_is_clean` — the compliant server must produce zero findings.
* `exact_rule_sets_match_the_fault_catalogue` — each faulty target yields
  exactly the rule ids its module documents, no more, no fewer.
* `findings_are_ranked_correctly` — every finding is ranked, and each faulty
  target has at least one critical.
