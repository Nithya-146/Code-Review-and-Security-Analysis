"""
Planted Security Vulnerabilities Sample.
Contains intentional security flaws for security_analysis agent.
"""

import hashlib
import os
import pickle
import sqlite3

# Hardcoded AWS access key secret
API_KEY = "AKIAIOSFODNN7EXAMPLE12345"


def fetch_user_data(conn: sqlite3.Connection, user_id: str):
    """SQL injection vulnerability via f-string in cursor.execute."""
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()


def run_system_ping(host: str) -> None:
    """Command injection vulnerability via os.system."""
    os.system("ping -c 1 " + host)


def calculate_weak_hash(token: str) -> str:
    """Weak cryptographic hashing using deprecated MD5."""
    return hashlib.md5(token.encode("utf-8")).hexdigest()


def deserialize_untrusted(raw_data: bytes):
    """Insecure deserialization using pickle.loads."""
    return pickle.loads(raw_data)
