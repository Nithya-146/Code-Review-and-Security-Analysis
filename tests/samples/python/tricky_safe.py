"""
Tricky Safe Python Sample.
Demonstrates secure and high-quality coding practices that must NOT trigger false positives.
"""

import hashlib
import os
import subprocess
import yaml
from pathlib import Path

# Safe Secret: Read from environment variable
SECRET_KEY = os.getenv("APP_SECRET_KEY", "default-dev-key")

# Safe Configuration
DEBUG = False


def safe_query_user(cursor, user_id: int):
    """Safe SQL: Parameterized query with bind variables."""
    query = "SELECT * FROM accounts WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()


def safe_run_command(host: str) -> None:
    """Safe Command: Process invocation without shell interpreter."""
    subprocess.run(["ping", "-c", "1", host], check=True)


def safe_cryptographic_hash(payload: bytes) -> str:
    """Safe Crypto: Modern SHA-256 secure hash."""
    return hashlib.sha256(payload).hexdigest()


def safe_yaml_parsing(raw_yaml: str):
    """Safe Deserialization: SafeLoader explicitly enforced."""
    return yaml.safe_load(raw_yaml)


def safe_file_reading(base_dir: Path, requested_name: str) -> str:
    """Safe Path Traversal: Path resolve and containment validation."""
    resolved_path = (base_dir / requested_name).resolve()
    if resolved_path.is_relative_to(base_dir):
        with open(resolved_path, "r", encoding="utf-8") as f:
            return f.read()
    raise PermissionError("Access denied: path outside base directory")
