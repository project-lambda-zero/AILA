.PHONY: install dev dev-up dev-down dev-reset dev-logs dev-status teardown teardown-force backend frontend frontend-build storybook worker worker-vuln worker-forensics worker-sbd db-init migrate test test-e2e test-frontend lint typecheck honesty build compile check security-scan audit bandit clean

# ── Setup ──
install:
	pip install -e ".[dev]"
	corepack enable
	pnpm install

# ── Dev infrastructure (Postgres + Redis via docker-compose) ──
dev-up:
	@command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is not installed."; exit 1; }
	docker compose -f infra/utilities/docker-compose.yml up -d
	@echo "Waiting for services to become healthy..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
		docker compose -f infra/utilities/docker-compose.yml ps postgres --format json 2>/dev/null | grep -q '"Health":"healthy"' && \
		docker compose -f infra/utilities/docker-compose.yml ps redis --format json 2>/dev/null | grep -q '"Health":"healthy"' && \
		echo "  ✓ postgres + redis healthy at localhost:5432 / localhost:6379" && exit 0; \
		sleep 2; \
	done; \
	echo "WARNING: services took longer than 24s to become healthy. Check 'make dev-logs'."

dev-down:
	docker compose -f infra/utilities/docker-compose.yml down

dev-reset:
	docker compose -f infra/utilities/docker-compose.yml down -v
	@echo "Volumes removed. 'make dev-up' will start with a fresh database."

teardown:
	@bash scripts/teardown.sh

teardown-force:
	@echo "WARNING: --force skips all confirmation prompts."
	@bash scripts/teardown.sh --force

dev-logs:
	docker compose -f infra/utilities/docker-compose.yml logs -f

dev-status:
	docker compose -f infra/utilities/docker-compose.yml ps

# ── Development ──
dev:
	@echo "AILA dev workflow:"
	@echo ""
	@echo "  1. Start infra (Postgres + Redis):"
	@echo "       make dev-up"
	@echo ""
	@echo "  2. Apply DB migrations (first run only):"
	@echo "       make migrate"
	@echo ""
	@echo "  3. In separate terminals:"
	@echo "       make backend       # uvicorn  on :8000"
	@echo "       make frontend      # vite     on :3000"
	@echo "       make worker        # default queue"
	@echo "       make worker-vuln   # vulnerability queue"
	@echo "       make worker-forensics"
	@echo "       make worker-sbd"
	@echo ""
	@echo "  4. Tear down infra when done:"
	@echo "       make dev-down      # keeps data volumes"
	@echo "       make dev-reset     # wipes data volumes"

backend: dev-up db-init
	@echo "Freeing port 8000 if held..."
	@fuser -k 8000/tcp 2>/dev/null || true
	uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload

frontend:
	@echo "Freeing port 3000 if held..."
	@fuser -k 3000/tcp 2>/dev/null || true
	pnpm --filter @aila/shell run dev

frontend-build:
	pnpm --filter @aila/shell run build

storybook:
	pnpm --filter @aila/shell run storybook

worker: dev-up db-init
	python -m aila worker

worker-vuln: dev-up db-init
	python -m aila worker -q vulnerability

worker-forensics: dev-up db-init
	python -m aila worker -q forensics

worker-sbd: dev-up db-init
	python -m aila worker -q sbd_nfr

db-init:
	@echo "Bootstrapping a fresh AILA database (create tables + stamp head)..."
	python scripts/db_init.py
	@echo "Database initialized. Run 'make migrate' to apply any future migrations."

migrate:
	cd src/aila && alembic upgrade head

# ── Quality ──
test:
	python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py -x

test-e2e:
	python -m pytest tests/test_e2e.py -v

test-frontend:
	pnpm --filter @aila/shell run test

lint:
	python -m ruff check src/aila/

typecheck:
	pnpm -r run type-check

honesty:
	python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py

build:
	pnpm --filter @aila/shell run build

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
	pnpm -r run clean 2>/dev/null || true
	@echo "Cleaned."
