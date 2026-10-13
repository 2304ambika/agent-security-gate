# Agent Security Gate

Feasibility prototype for idea 1 from [arXiv:2605.18991](https://arxiv.org/abs/2605.18991) (*Agent Security is a Systems Problem*): treat the model as untrusted and enforce **complete mediation** via a deterministic TCB reference monitor before every tool call.

## What it implements

| Paper principle | Mechanism here |
| --- | --- |
| Complete mediation | `SecurityTCB.invoke` is the only tool path |
| Least privilege | Task-scoped RBAC (`roles.py`) |
| TCB tamper resistance | Deterministic detectors (no LLM in the monitor) |
| Instruction / data separation | `TrustLevel.EXTERNAL` content cannot carry executable policy |
| Secure information flow | DNS exfil + secret-in-args checks |
| Learning | Confirmed FNs promote hosts/patterns into policy |

## Run

```bash
python3 demo.py
python3 benchmarks/run_bench.py
python3 tests/test_gate.py
```

Metrics land in `results/metrics.json`.

## Metrics (what “good” looks like)

- **attack_block_rate_tpr** → 1.0 ideal
- **false_positive_rate** → 0.0 ideal
- **complete_mediation_rate** → must be 1.0 (architecture invariant)
- **privilege_reduction** → higher means tighter task roles
- **latency_ms** → monitor overhead (should be << model time)
- **f1** → overall quality of allow/deny decisions on the labeled set
