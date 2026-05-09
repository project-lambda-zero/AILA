.PHONY: install dev dev-all dev-up dev-down dev-reset dev-logs dev-status teardown teardown-force backend frontend frontend-build storybook worker worker-vuln worker-forensics worker-sbd db-init migrate test test-e2e test-frontend lint typecheck honesty build compile check security-scan audit bandit clean

# Cross-platform: use python for port-freeing and cleanup instead of
# fuser/find/bash which are Linux-only.

# ── Setup ──
install:
	pip install -e ".[dev]"
	corepack enable
	pnpm install

# ── Dev infrastructure (Postgres + Redis via docker-compose) ──
dev-up:
	docker compose -f infra/utilities/docker-compose.yml up -d
	@echo "Waiting for services..."
	python -c "import time, socket; [time.sleep(2) or None for _ in range(12) if socket.socket().connect_ex(('127.0.0.1',5432))]; print('  postgres + redis ready')"

dev-down:
	docker compose -f infra/utilities/docker-compose.yml down

dev-reset:
	docker compose -f infra/utilities/docker-compose.yml down -v
	@echo "Volumes removed. 'make dev-up' will start with a fresh database."

teardown:
	python -c "import subprocess,sys; subprocess.call([sys.executable, 'scripts/teardown.py'] if sys.platform=='win32' else ['bash','scripts/teardown.sh'])"

teardown-force:
	@echo "WARNING: --force skips all confirmation prompts."
	python -c "import subprocess,sys; subprocess.call([sys.executable, 'scripts/teardown.py','--force'] if sys.platform=='win32' else ['bash','scripts/teardown.sh','--force'])"

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
	python scripts/portfree.py 8000
	uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload

# Start ALL services in one terminal (Ctrl+C stops everything)
dev-all: dev-up
	python scripts/dev_all.py

frontend:
	python scripts/portfree.py 3000
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
	python scripts/db_init.py

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
	python -c "import shutil,pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"
	python -c "import pathlib; [p.unlink() for p in [pathlib.Path('.coverage'), pathlib.Path('coverage.json')] if p.exists()]"
	pnpm -r run clean 2>nul || pnpm -r run clean 2>/dev/null || echo "pnpm clean done"
	@echo "Cleaned."
