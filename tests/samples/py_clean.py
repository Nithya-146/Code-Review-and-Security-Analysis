"""
Clean Python Evaluation Sample (Milestone 4).
Well-structured, secure, maintainable module with zero planted issues
used to verify zero false positives.
"""

import hashlib
import html
import os
import sqlite3
from typing import Dict, List, Optional, Tuple

DEFAULT_TAX_RATE = 0.08
DEFAULT_TIMEOUT_SECONDS = 10


class InvoiceRepository:
    """Secure, concise repository for reading and formatting invoice summaries."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        """Stores an active SQLite database connection."""
        self.connection = connection

    def get_api_token(self) -> str:
        """Reads the integration token safely from environment variables."""
        return os.environ.get("INVOICE_API_TOKEN", "")

    def fetch_invoice(self, invoice_id: str) -> Optional[Tuple[str, float]]:
        """Fetches a single invoice row using parameterized SQL binding."""
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT invoice_id, total_amount FROM invoices WHERE invoice_id = ?",
            (invoice_id,),
        )
        return cursor.fetchone()

    def format_safe_html_label(self, customer_name: str) -> str:
        """Escapes untrusted display strings before inserting into HTML."""
        escaped_name = html.escape(customer_name, quote=True)
        return f"<span class='customer'>{escaped_name}</span>"

    def compute_integrity_digest(self, payload: bytes) -> str:
        """Generates a strong SHA-256 checksum for invoice payloads."""
        return hashlib.sha256(payload).hexdigest()

    def calculate_total_with_tax(self, subtotal: float) -> float:
        """Computes invoice total using a named module-level tax constant."""
        if subtotal <= 0.0:
            return 0.0
        return round(subtotal * (1.0 + DEFAULT_TAX_RATE), 2)

    def parse_quantity(self, raw_qty: str) -> int:
        """Parses an integer quantity catching only ValueError."""
        try:
            parsed = int(raw_qty.strip())
            return max(0, parsed)
        except ValueError:
            return 0

    def summarize_balances(self, records: List[Dict[str, float]]) -> float:
        """Sums positive balances across a list of invoice dictionaries."""
        running_total = 0.0
        for item in records:
            amount = item.get("amount", 0.0)
            if amount > 0.0:
                running_total += amount
        return round(running_total, 2)

