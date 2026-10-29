#!/usr/bin/env bash
# Refresh external agent-security corpora used by run_external_bench.py
set -euo pipefail
UA='Mozilla/5.0 (compatible; agent-security-gate/1.0)'
ROOT="$(cd "$(dirname "$0")" && pwd)/external"
mkdir -p "$ROOT"/{hendar,lakera_b3,injecagent,agentharm,a3s,coding_agent,prepared}

dl() { echo "GET $2"; curl -fsSL -A "$UA" -L -o "$1" "$2"; echo "  $(wc -c < "$1") bytes"; }

dl "$ROOT/hendar/prompt_injection.jsonl" \
  "https://huggingface.co/datasets/h0000w/hendar-agentic-ai-dataset/resolve/main/data/prompt_injection.jsonl"
dl "$ROOT/hendar/unsafe_tool_requests.jsonl" \
  "https://huggingface.co/datasets/h0000w/hendar-agentic-ai-dataset/resolve/main/data/unsafe_tool_requests.jsonl"
dl "$ROOT/hendar/policy_decisions.jsonl" \
  "https://huggingface.co/datasets/h0000w/hendar-agentic-ai-dataset/resolve/main/data/policy_decisions.jsonl"
dl "$ROOT/hendar/multi_agent_tasks.jsonl" \
  "https://huggingface.co/datasets/h0000w/hendar-agentic-ai-dataset/resolve/main/data/multi_agent_tasks.jsonl"

dl "$ROOT/lakera_b3/selected_attacks_low-quality.csv" \
  "https://huggingface.co/datasets/Lakera/b3-agent-security-benchmark-weak/resolve/main/selected_attacks_low-quality.csv"

dl "$ROOT/agentharm/harmful_behaviors_test_public.json" \
  "https://huggingface.co/datasets/ai-safety-institute/AgentHarm/resolve/main/benchmark/harmful_behaviors_test_public.json"

dl "$ROOT/a3s/injected.json" \
  "https://huggingface.co/datasets/inclusionAI/A3S-Bench/resolve/main/data/advance/injected.json"

for f in test_cases_dh_enhanced.json test_cases_ds_enhanced.json; do
  dl "$ROOT/injecagent/$f" \
    "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/$f"
done

echo "Rebuilding prepared hard subsets…"
python3 "$(dirname "$0")/prepare_hard_sets.py"
echo "Done. Run: python3 benchmarks/run_external_bench.py"
