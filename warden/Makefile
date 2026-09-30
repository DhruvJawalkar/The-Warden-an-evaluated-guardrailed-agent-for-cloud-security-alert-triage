PY ?= python3
export PYTHONPATH := src

.PHONY: gen run test lint clean

gen:            ## regenerate datasets/v1 (deterministic)
	$(PY) -m warden.data.generator --out datasets/v1 --seed 20260903 --count 20

run:            ## triage one incident, e.g. make run ID=WRD-0001
	$(PY) -m warden.loop.agent_loop --incident $(ID)

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests

clean:
	rm -rf runs .pytest_cache .ruff_cache
