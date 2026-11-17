"""
Held-Out Clean Python Sample: Task Scheduler Helper.
Well-structured, secure, idiomatic Python with zero planted defects
to evaluate false-positive rate on unseen clean code.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
from typing import Dict, List, Optional

DEFAULT_POLL_INTERVAL = 30
MAX_BATCH_SIZE = 50


@dataclass(frozen=True)
class ScheduledJob:
    """Represents a single queued background task."""

    job_id: str
    task_name: str
    priority: int


class TaskSchedulerStore:
    """Safe repository and helper utilities for scheduled background jobs."""

    def __init__(self, conn: sqlite3.Connection, workspace_root: str) -> None:
        """Initializes store with database connection and workspace root."""
        self.conn = conn
        self.workspace_root = Path(workspace_root).resolve()

    def load_signing_secret(self) -> str:
        """Loads signing credential safely from environment variables."""
        return os.environ.get("SCHEDULER_SIGNING_KEY", "")

    def generate_run_token(self) -> str:
        """Generates a cryptographically secure random job execution token."""
        return secrets.token_hex(16)

    def fetch_job_by_id(self, job_id: str) -> Optional[tuple]:
        """Retrieves a job record using parameterized SQL placeholders."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT job_id, task_name, priority FROM jobs WHERE job_id = ?",
            (job_id,),
        )
        return cursor.fetchone()

    def compute_payload_checksum(self, payload: bytes) -> str:
        """Computes a SHA-256 integrity checksum over job payload bytes."""
        return hashlib.sha256(payload).hexdigest()

    def read_safe_config(self, relative_name: str) -> str:
        """Reads a config file only after verifying path containment."""
        candidate = (self.workspace_root / Path(relative_name).name).resolve()
        if not candidate.is_relative_to(self.workspace_root):
            raise ValueError("Path escapes scheduler workspace")
        return candidate.read_text(encoding="utf-8")

    def run_health_probe(self, probe_label: str) -> subprocess.CompletedProcess:
        """Executes an argument-list command safely with shell=False."""
        return subprocess.run(["echo", probe_label], shell=False, check=True, capture_output=True, text=True)

    def parse_priority(self, raw_priority: str) -> int:
        """Parses integer priority while catching only ValueError."""
        try:
            value = int(raw_priority.strip())
            return min(max(0, value), MAX_BATCH_SIZE)
        except ValueError:
            return 0

    def group_by_task(self, jobs: List[ScheduledJob]) -> Dict[str, int]:
        """Counts queued jobs grouped by task name."""
        counts: Dict[str, int] = {}
        for job in jobs:
            counts[job.task_name] = counts.get(job.task_name, 0) + 1
        return counts

