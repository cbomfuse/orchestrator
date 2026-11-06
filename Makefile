.PHONY: install test selftest run evaluate report clean

PY ?= python3
RUN ?= latest

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

## Pipeline check without Docker/CodeQL: replays the reference CBOM (and a degraded copy) through everything.
selftest:
	orchestrator run --tool oracle --tool oracle-noisy --run-id selftest

## Newest release of every enabled tool against the current baseline.
run:
	orchestrator -v run

evaluate:
	orchestrator evaluate $(RUN)

report:
	orchestrator report $(RUN)

clean:
	rm -rf results/selftest .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
