# Integrated compiler and store checkpoint

Frozen source `15e64dd4a47730d9b558561afaac7b24ef324d1a` / tree `aae6a9b0918d8b95db2c1d177dad1e99e86623d6` ran unchanged with
Rust 1.97.1. The cohort **failed** at strict store lint after the preceding gates
passed. Original deadlines and stop-on-first-failure ordering were preserved.

| Gate | Outcome | Seconds |
| --- | --- | --- |
| workspace-all-targets-check | passed | 134.082 |
| workspace-format | passed | 1.546 |
| complete-store-library | passed | 86.053 |
| strict-store | failed | 29.221 |

The storage result was 143 passed, zero failed and two ignored. All 48 required
storage regressions passed. The ignored entries are an externally configured
MinIO live test and a subprocess helper invoked by the passing crash recovery
parent test. No live MinIO or full release qualification is claimed.

Strict lint reported unusual UUID literal grouping, an overly complex registry
static type, and a collapsible conditional. Successor `654c074` corrects those
without altering ownership or storage behavior. All 20 later gates, including
new signer/startup/receipt behavior, were withheld and remain required. Every
dispatched process group drained without signals or uncertain cleanup. Source
comparison passed. The eight raw files are copied unchanged with SHA-256 values
in `copied-files.json`; test executable identity and preserved local path are in
the original evidence. Final platform, live services, capacity and endurance
acceptance remain open.
