"""
CyberGuard AI - Asynchronous Background Task Queue & Job Dispatcher
Manages non-blocking execution of telemetry processing, YARA scanning, and report generation.
"""

import time
import uuid
import threading
import queue
import logging
from typing import Callable, Dict, Any, Optional

logger = logging.getLogger("CyberGuard.TaskQueue")

class BackgroundTaskQueue:
    def __init__(self, max_workers: int = 4):
        self.task_queue: queue.Queue = queue.Queue()
        self.job_results: Dict[str, Dict[str, Any]] = {}
        self.workers: list = []
        self.is_running = True

        for i in range(max_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True, name=f"CyberWorker-{i+1}")
            t.start()
            self.workers.append(t)

    def _worker_loop(self):
        while self.is_running:
            try:
                job_id, fn, args, kwargs = self.task_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            self.job_results[job_id]["status"] = "RUNNING"
            start_t = time.time()
            try:
                res = fn(*args, **kwargs)
                elapsed = (time.time() - start_t) * 1000
                self.job_results[job_id]["status"] = "SUCCESS"
                self.job_results[job_id]["result"] = res
                self.job_results[job_id]["duration_ms"] = round(elapsed, 2)
            except Exception as e:
                elapsed = (time.time() - start_t) * 1000
                logger.error(f"Task {job_id} failed: {e}", exc_info=True)
                self.job_results[job_id]["status"] = "FAILED"
                self.job_results[job_id]["error"] = str(e)
                self.job_results[job_id]["duration_ms"] = round(elapsed, 2)
            finally:
                self.task_queue.task_done()

    def submit_task(self, fn: Callable, *args, **kwargs) -> str:
        job_id = f"job-{uuid.uuid4().hex[:10]}"
        self.job_results[job_id] = {
            "job_id": job_id,
            "status": "QUEUED",
            "submitted_at": time.time(),
            "result": None,
            "error": None
        }
        self.task_queue.put((job_id, fn, args, kwargs))
        return job_id

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self.job_results.get(job_id)

GLOBAL_TASK_QUEUE = BackgroundTaskQueue()
