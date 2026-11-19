# Fidelity of the report in `reports/`

These reports were produced by running each target as its own OS process and
probing it over loopback TCP — no in-process shortcuts.

## Expectation vs result

| impl | planted faults (rules) | reported | verdict |
|------|------------------------|----------|---------|
| `reference` | none | 0 findings | correct — an oracle that gets flagged would invalidate every other result |
| `eager` | early `APP_DATA`/`REKEY`/`CLOSE` (R-3.7) | 4 critical, all R-3.7 | correct |
| `lenient` | unchecked `seq` (R-4.3), swallowed auth failures (R-4.2) | 2 critical R-4.3, 2 minor R-4.2 | correct |
| `sticky` | reusable ticket (R-6.4), retired epoch (R-5.4), mid-session resume (R-6.2) | 2 critical R-6.4, 1 critical R-6.2, 1 critical R-5.4 | correct |

`eager` reports four findings under one rule because each *action* that is
wrongly accepted is its own finding: three different message types
(`APP_DATA`, `REKEY`, `CLOSE`) plus the gap variant of `APP_DATA`. That is
the right granularity for reproduction — they are four distinct scripts.

## Deliberate non-findings

Two classes of divergence are intentionally **not** reported as findings,
and the reason is stated in the code (`explore::tolerant`):

* **Closed-without-ERR** to something forbidden: closing is at least as safe
  as the required `ERR` + close, and is a common hardening choice. Reporting
  it as critical would be noise, not signal.
* **Wrong error code for a malformed/forged resume on an already-established
  connection**: the phase's own rule (R-6.2) is what matters there, and the
  server is rejecting either way.

Both are defensible protocol behaviour, not the ordering bugs this bench
exists to find. Anything the target *actually accepted* is always reported.

## Reproducing

Each finding in a report carries a protocol script and the exact hex of the
last frame. `scp-probe --replay-phase … --replay-action …` re-executes the
case and prints the frame-by-frame transcript; it is the same code path the
explorer uses, so a fixed target stops reproducing and a regressed one does
again.

## Determinism

`findings_are_stable_across_runs` probes every faulty target twice end to end
and requires identical rule sets; `reference_is_clean` requires zero findings
under every budget tried. The two together are what make a report
trustworthy: the same input bytes produce the same verdict, and a correct
implementation is never flagged.
