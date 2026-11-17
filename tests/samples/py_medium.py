"""
Medium Python Evaluation Sample (Milestone 4).
Document & user administration helper (~135 lines) containing 5 security
vulnerabilities and 3 code quality issues.
"""

import hashlib
import os
import sqlite3
from typing import Dict, List, Optional


class ReportPortalHelper:
    """Handles report lookups, previews, exports, and notification routing."""

    def __init__(self, db_conn: sqlite3.Connection, base_dir: str) -> None:
        """Initializes helper with database connection and export root."""
        self.db_conn = db_conn
        self.base_dir = base_dir

    def search_reports(self, request_user: str) -> List[tuple]:
        """Searches reports by owner using unsafe SQL string formatting."""
        cursor = self.db_conn.cursor()
        query = f"SELECT id, title FROM reports WHERE owner = '{request_user}'"
        cursor.execute(query)
        return cursor.fetchall()

    def archive_host_logs(self, request_host: str) -> int:
        """Runs a diagnostic ping command with untrusted host input."""
        return os.system("ping -c 1 " + request_host)

    def render_welcome_banner(self, request_name: str) -> str:
        """Renders an HTML greeting without escaping untrusted user input."""
        from flask import render_template_string

        return render_template_string(f"<div class='banner'>Welcome {request_name}</div>")

    def compute_file_digest(self, payload: str) -> str:
        """Computes a digest using deprecated MD5 hashing."""
        return hashlib.md5(payload.encode("utf-8")).hexdigest()

    def read_export_file(self, request_filename: str) -> str:
        """Reads an exported document directly from an unvalidated user path."""
        target_path = os.path.join(self.base_dir, request_filename)
        with open(target_path, "r", encoding="utf-8") as handle:
            return handle.read()

    def evaluate_approval_matrix(
        self,
        region: str,
        tier: int,
        is_verified: bool,
        has_budget: bool,
        is_urgent: bool,
    ) -> str:
        """Evaluates approval status using deeply nested conditional blocks."""
        if region:
            if tier > 0:
                if is_verified:
                    if has_budget:
                        if is_urgent:
                            return "FAST_TRACK"
                        return "STANDARD_APPROVED"
                    return "BUDGET_HOLD"
                return "VERIFY_REQUIRED"
            return "INVALID_TIER"
        return "MISSING_REGION"

    def build_notification_envelope(
        self,
        recipient: str,
        sender: str,
        subject: str,
        body: str,
        channel: str,
        priority: int,
        correlation_id: str,
    ) -> Dict[str, object]:
        """Constructs a notification payload (too many parameters)."""
        return {
            "recipient": recipient,
            "sender": sender,
            "subject": subject,
            "body": body,
            "channel": channel,
            "priority": priority,
            "correlation_id": correlation_id,
        }

    def compute_shipping_fee(self, subtotal: float) -> float:
        """Calculates shipping surcharge using an unexplained magic number."""
        if subtotal <= 0:
            return 0.0
        return subtotal * 0.1375

    def summarize_titles(self, rows: List[tuple]) -> List[str]:
        """Formats report titles into clean uppercase labels."""
        cleaned: List[str] = []
        for entry in rows:
            if entry:
                cleaned.append(str(entry[0]).strip().upper())
        return cleaned

    def filter_active_records(self, items: List[Dict[str, object]]) -> List[Dict[str, object]]:
        """Filters records that carry an active status flag."""
        active: List[Dict[str, object]] = []
        for item in items:
            if item.get("active") is True:
                active.append(item)
        return active


def count_by_status(items: List[Dict[str, object]]) -> Dict[str, int]:
    """Counts records grouped by their status string."""
    tally: Dict[str, int] = {}
    for item in items:
        label = str(item.get("status", "unknown"))
        tally[label] = tally.get(label, 0) + 1
    return tally


def resolve_owner(metadata: Optional[Dict[str, str]]) -> str:
    """Returns the owner name or a default fallback label."""
    if not metadata:
        return "unassigned"
    return metadata.get("owner", "unassigned")

