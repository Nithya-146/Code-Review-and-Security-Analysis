"""
Held-Out Python Sample 1: Billing & Statement Worker.
Functional style with realistic benign helpers plus 5 planted issues:
- SQL injection via %-formatting on db.execute(stmt)
- Command injection via subprocess.Popen(..., shell=True)
- Weak SHA-1 hashing for webhook signature digest
- Too many parameters in dispatch_statement
- Broad exception handler in parse_exchange_rate
"""

from dataclasses import dataclass
import hashlib
import subprocess
from typing import Dict, List, Optional

STANDARD_CURRENCY = "USD"
MAX_RETRY_COUNT = 3


@dataclass(frozen=True)
class StatementSummary:
    """Immutable billing statement summary record."""

    account_code: str
    total_cents: int
    currency: str = STANDARD_CURRENCY


def format_money(cents: int, currency: str = STANDARD_CURRENCY) -> str:
    """Formats an integer cent amount into a human-readable currency string."""
    dollars = cents / 100.0
    return f"{currency} {dollars:,.2f}"


def mark_invoice_status(db, invoice_code: str, new_status: str) -> None:
    """Updates an invoice status row using legacy %-formatted SQL."""
    stmt = "UPDATE invoices SET status = '%s' WHERE code = '%s'" % (new_status, invoice_code)
    db.execute(stmt)


def render_pdf_invoice(template_arg: str) -> subprocess.Popen:
    """Invokes wkhtmltopdf through a shell command with untrusted argument."""
    cmd = f"wkhtmltopdf {template_arg} /tmp/statement.pdf"
    return subprocess.Popen(cmd, shell=True)


def compute_webhook_fingerprint(raw_body: str) -> str:
    """Computes a legacy SHA-1 digest of incoming webhook payloads."""
    return hashlib.sha1(raw_body.encode("utf-8")).hexdigest()


def parse_exchange_rate(raw_rate: str) -> float:
    """Parses a decimal exchange rate with an overly broad exception catch."""
    try:
        rate = float(raw_rate.strip())
        return rate if rate > 0.0 else 1.0
    except Exception:
        return 1.0


def dispatch_statement(
    account_code: str,
    billing_period: str,
    currency: str,
    locale: str,
    delivery_mode: str,
    retry_limit: int,
    dry_run: bool,
) -> Dict[str, object]:
    """Builds a dispatch payload for customer statements (7 parameters)."""
    capped_retries = min(max(0, retry_limit), MAX_RETRY_COUNT)
    return {
        "account": account_code,
        "period": billing_period,
        "currency": currency,
        "locale": locale,
        "mode": delivery_mode,
        "retries": capped_retries,
        "dry_run": dry_run,
    }


def aggregate_totals(records: List[StatementSummary]) -> Optional[int]:
    """Sums cent totals across a non-empty list of statement summaries."""
    if not records:
        return None
    return sum(item.total_cents for item in records)

