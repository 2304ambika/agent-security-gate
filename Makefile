# Run `make help`. Logs -> logs/, metrics -> results/{offline,llm}/
export PYTHONPATH := src
PY ?= python3
VENV_PY ?= .venv/bin/python

.PHONY: help demo test ideas cross bench split split-internal external llm-eval live-mock live-attack live-benign
help:
	@echo "NO LLM:   make test | demo | ideas | cross | bench | split | split-internal | external"
	@echo "MOCK:     make live-mock            (scripted agent, no key)"
	@echo "LOCAL LLM (ollama serve running): make llm-eval MODEL=llama3.2 N=3"
	@echo "CLAUDE API (key + credits): make live-attack | live-benign"

demo:
	$(PY) examples/demo.py
test:
	$(PY) tests/test_gate.py && $(PY) tests/test_session_and_updates.py
ideas:            ## idea 1 (session gating, red-team variants) + idea 2 (policy learning, in-repo tiers)
	$(PY) benchmarks/runners/run_ideas_bench.py
cross:            ## idea 2 on external data: train on datasets, test on separate benchmarks
	$(PY) benchmarks/runners/run_cross_dataset_bench.py
bench:            ## synthetic scenarios, easy/hard/held_out + cross-val
	$(PY) benchmarks/runners/run_bench.py -v > logs/bench.log 2>&1; tail -6 logs/bench.log
split:            ## pooled internal+external, 70/30 grouped split
	$(PY) benchmarks/runners/run_split_bench.py > logs/split.log 2>&1; tail -14 logs/split.log
split-internal:   ## same, synthetic only, with per-call logs
	$(PY) benchmarks/runners/run_split_bench.py --suites internal -v > logs/split_internal.log 2>&1; tail -6 logs/split_internal.log
external:         ## external suites, no split
	$(PY) benchmarks/runners/run_external_bench.py > logs/external.log 2>&1; tail -14 logs/external.log
MODEL ?= llama3.2
N ?= 3
llm-eval:
	$(PY) benchmarks/llm/llm_eval.py --model $(MODEL) --n $(N) > logs/llm_eval.log 2>&1; tail -3 logs/llm_eval.log
live-mock:
	$(VENV_PY) benchmarks/llm/live_agent.py --mock --attack > logs/live_mock_attack.log 2>&1; cat logs/live_mock_attack.log
live-attack:
	$(VENV_PY) benchmarks/llm/live_agent.py --attack > logs/live_attack.log 2>&1; tail -20 logs/live_attack.log
live-benign:
	$(VENV_PY) benchmarks/llm/live_agent.py > logs/live_benign.log 2>&1; tail -20 logs/live_benign.log
