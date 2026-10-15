# Agent Security Gate

Feasibility prototype for idea 1 from [arXiv:2605.18991](https://arxiv.org/abs/2605.18991): treat the model as untrusted and enforce **complete mediation** via a deterministic TCB reference monitor before every tool call.

## Harness loop

```text
policy = baseline
for tier in easy → hard → held_out:
  score(tier)                         # before
  if tier in {easy, hard}:
    absorb each false negative        # trusted labels
  score(tier)                         # after
  # policy warm-starts into next tier
```

- **Gate code stays frozen** — difficulty lives in `benchmarks/scenarios.py` only.
- **held_out** never trains; it measures whether learned hosts/patterns generalize.

## Run

```bash
python3 demo.py
python3 benchmarks/run_bench.py
python3 tests/test_gate.py
```

Metrics → `results/metrics.json`.

## How to read tier deltas

| Signal | Meaning |
| --- | --- |
| easy before ≈ after ≈ 1.0 | Baseline fits canonical attacks |
| hard before TPR drop | Obfuscation / novel phrasing beats heuristics |
| hard after TPR lift | Learning from labeled FNs works on *seen* attacks |
| held_out TPR flat | String/host promotion often does **not** generalize |
| hard FPR > 0 | e.g. security blogs quoting attack phrases (EXTERNAL) |
