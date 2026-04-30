.PHONY: install dev backend frontend worker worker-vuln worker-forensics migrate test test-e2e lint typecheck honesty build compile check security-scan audit bandit clean

# ── Setup ──
install:
	pip install -e ".[dev]"
	cd frontend && npm install

# ── Development ──
dev:
	@echo "Starting backend, frontend, and worker..."
	@echo "Run each in a separate terminal:"
	@echo "  make backend"
	@echo "  make frontend"
	@echo "  make worker"

backend:
	uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload

frontend:
	cd frontend && npm run dev

worker:
	python -m aila worker

worker-vuln:
	python -m aila worker -q vulnerability

worker-forensics:
	python -m aila worker -q forensics

migrate:
	cd src/aila && alembic upgrade head

# ── Quality ──
test:
	python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py -x

test-e2e:
	python -m pytest tests/test_e2e.py -v

lint:
	python -m ruff check src/aila/

typecheck:
	cd frontend && npm run typecheck

honesty:
	python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py

build:
	cd frontend && npm run build

compile:
	python -m compileall -q src/aila

check: lint honesty compile typecheck
	@echo "All gates passed."

# ── Security ──
security-scan: audit bandit
	@echo "Security scan complete."

audit:
	pip-audit --strict --desc

bandit:
	bandit -r src/aila -q -ll

# ── Cleanup ──
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -f .coverage coverage.json
	@echo "Cleaned."
