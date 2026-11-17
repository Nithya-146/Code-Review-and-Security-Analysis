"""
Small Python Evaluation Sample (Milestone 4).
Single-file account lookup helper with 3 planted issues:
- Hardcoded API secret (CWE-798)
- SQL injection via f-string (CWE-89)
- Broad exception handler (broad_exception)
"""

import sqlite3
from typing import Optional, Tuple

# Hardcoded service credential
SERVICE_API_KEY = "AKIAIOSFODNN7EXAMPLE99999"


def format_account_label(account_id: str, owner: str) -> str:
    """Formats a readable display label for an account record."""
    clean_owner = owner.strip() or "Unknown"
    return f"{account_id}:{clean_owner}"


def lookup_account(conn: sqlite3.Connection, account_id: str) -> Optional[Tuple]:
    """Fetches an account record using an unsafe formatted SQL query."""
    cursor = conn.cursor()
    query = f"SELECT id, owner, balance FROM accounts WHERE id = '{account_id}'"
    cursor.execute(query)
    return cursor.fetchone()


def parse_positive_amount(raw_value: str) -> float:
    """Parses a numeric amount string with an overly broad exception catch."""
    try:
        parsed = float(raw_value)
        if parsed < 0:
            return 0.0
        return parsed
    except Exception:
        return 0.0

