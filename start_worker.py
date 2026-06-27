"""Worker startup shim -- fresh SelectorEventLoop installed right before arq.run_worker."""
import sys as _sys
from urllib.parse import urlparse

queue = _sys.argv[1] if len(_sys.argv) > 1 else "default"
redis_url = _sys.argv[2] if len(_sys.argv) > 2 else "redis://127.0.0.1:6379"

parsed = urlparse(redis_url)
redis_host = parsed.hostname or "127.0.0.1"
redis_port = parsed.port or 6379

# Do all heavy imports first -- they may touch asyncio/asyncpg and disturb the loop.
import arq
from aila.platform.tasks.worker import WorkerSettings, reaper
from aila.platform.tasks import get_task_tuning
from aila.platform.tasks.constants import ARQ_JOB_TIMEOUT_S, ARQ_KEEP_RESULT_S, ARQ_MAX_TRIES

class _W(WorkerSettings):
    queue_name = f"arq:queue:{queue}"
    redis_settings = arq.connections.RedisSettings(host=redis_host, port=redis_port)
    cron_jobs = [arq.cron(reaper, second=0)]
    job_timeout = get_task_tuning("arq_job_timeout_s", ARQ_JOB_TIMEOUT_S)
    keep_result = get_task_tuning("arq_keep_result_s", ARQ_KEEP_RESULT_S)
    max_tries = get_task_tuning("arq_max_tries", ARQ_MAX_TRIES)
    functions = WorkerSettings.functions
    on_startup = WorkerSettings.on_startup
    on_job_start = WorkerSettings.on_job_start
    on_job_end = WorkerSettings.on_job_end

# Install a fresh SelectorEventLoop AFTER all imports, immediately before arq.
# Imports may create+close asyncio loops (e.g. asyncpg cleanup), leaving the
# thread-local loop in a closed/None state. arq.Worker.__init__ calls
# asyncio.get_event_loop() -- it must find an open SelectorEventLoop on Windows.
import asyncio
if _sys.platform == "win32":
    loop = asyncio.SelectorEventLoop()
    asyncio.set_event_loop(loop)

print(f"Starting ARQ worker for queue='{queue}', redis='{redis_host}:{redis_port}'", flush=True)
arq.run_worker(_W)
