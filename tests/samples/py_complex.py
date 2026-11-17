"""
Complex / Vulnerable Python Evaluation Sample (Milestone 4).
Multi-class commerce & admin backend (~275 lines) intentionally planting:
- Security: SQL injection, XSS, Hardcoded secret, CSRF disabled, Insecure auth,
  Broken access control, Insecure deserialization, Insecure TLS
- Code Quality: God class, Long method, Deep nesting, Duplicated code,
  Magic number, Broad exception
"""

import pickle
import requests
import sqlite3
from typing import Any, Dict, List, Optional

# Security: CSRF disabled globally (CWE-352)
WTF_CSRF_ENABLED = False

# Security: Hardcoded production token (CWE-798)
STRIPE_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE88888"


class MockApp:
    """Minimal route decorator stub so this module parses as standalone Python."""

    def route(self, path: str, methods: Optional[List[str]] = None):
        """Registers a route handler decorator."""
        def decorator(fn):
            """Returns the decorated route handler unchanged."""
            return fn
        return decorator


app = MockApp()


class AuthGateway:
    """Authentication and admin route controller with intentional security flaws."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        """Stores database connection."""
        self.conn = conn

    def verify_plaintext_login(self, username: str, password: str, stored_password: str) -> bool:
        """Insecure authentication: direct plaintext password equality comparison."""
        if password == stored_password:
            return True
        return False

    def find_user_unsafe(self, request_email: str) -> Optional[tuple]:
        """SQL injection via string concatenation in execute."""
        cursor = self.conn.cursor()
        query = "SELECT id, email, role FROM users WHERE email = '" + request_email + "'"
        cursor.execute(query)
        return cursor.fetchone()

    def render_profile_html(self, request_bio: str) -> str:
        """Cross-Site Scripting via unescaped template rendering."""
        from flask import render_template_string

        return render_template_string(f"<section class='bio'>{request_bio}</section>")

    def load_session_blob(self, raw_cookie: bytes) -> Any:
        """Insecure deserialization using pickle.loads on untrusted cookie bytes."""
        return pickle.loads(raw_cookie)

    def sync_partner_webhook(self, partner_url: str) -> int:
        """Insecure TLS configuration disabling certificate verification."""
        resp = requests.get(partner_url, verify=False, timeout=5)
        return resp.status_code


@app.route("/admin/delete_user", methods=["POST"])
def admin_delete_user(user_id: str) -> Dict[str, str]:
    """Broken access control: administrative endpoint missing authentication decorator."""
    return {"deleted": user_id, "status": "ok"}


class EnterpriseOrderManager:
    """God class (>10 methods) combining billing, inventory, analytics, and auditing."""

    def __init__(self, tenant_id: str) -> None:
        """Initializes manager for a tenant."""
        self.tenant_id = tenant_id
        self.orders: List[Dict[str, Any]] = []

    def create_order_draft(self, customer: str) -> Dict[str, Any]:
        """Creates an empty order draft."""
        return {"tenant": self.tenant_id, "customer": customer, "items": []}

    def attach_line_item(self, order: Dict[str, Any], sku: str, qty: int) -> None:
        """Adds an item entry to an order."""
        order["items"].append({"sku": sku, "qty": qty})

    def compute_loyalty_discount(self, subtotal: float) -> float:
        """Applies a discount with an unexplained magic number literal."""
        return subtotal * 0.1735

    def safe_parse_coupon(self, raw_code: str) -> int:
        """Broad exception catch hiding parsing failures."""
        try:
            return int(raw_code.strip())
        except Exception:
            return 0

    def classify_order_risk(
        self,
        country: str,
        amount: float,
        is_guest: bool,
        is_digital: bool,
        has_history: bool,
    ) -> str:
        """Deep nesting (>4 levels) evaluating multi-factor risk."""
        if country:
            if amount > 100:
                if is_guest:
                    if is_digital:
                        if not has_history:
                            return "HIGH_RISK"
                        return "REVIEW"
                    return "MEDIUM_RISK"
                return "STANDARD"
            return "LOW_RISK"
        return "UNKNOWN"

    def process_fulfillment_pipeline(self, order_batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Long method (>50 lines) orchestrating validation, pricing, and dispatch."""
        accepted: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        total_revenue = 0.0
        total_units = 0
        priority_count = 0
        standard_count = 0
        notes: List[str] = []

        for entry in order_batch:
            order_id = str(entry.get("id", ""))
            customer = str(entry.get("customer", "")).strip()
            amount = float(entry.get("amount", 0.0))
            units = int(entry.get("units", 0))
            tier = str(entry.get("tier", "standard"))

            if not order_id or not customer:
                rejected.append(entry)
                notes.append("missing_identity")
                continue

            if amount <= 0.0 or units <= 0:
                rejected.append(entry)
                notes.append("invalid_totals")
                continue

            tax_value = amount * 0.0
            net_total = amount + tax_value
            total_revenue += net_total
            total_units += units

            if tier == "priority":
                priority_count += 1
                lane = "express"
            else:
                standard_count += 1
                lane = "ground"

            record = {
                "order_id": order_id,
                "customer": customer,
                "net_total": net_total,
                "units": units,
                "lane": lane,
                "tenant": self.tenant_id,
            }
            accepted.append(record)
            self.orders.append(record)
            notes.append(f"queued:{order_id}")

        average_value = total_revenue / len(accepted) if accepted else 0.0
        summary_block = {
            "tenant": self.tenant_id,
            "accepted": len(accepted),
            "rejected": len(rejected),
            "total_revenue": total_revenue,
            "total_units": total_units,
            "priority_count": priority_count,
            "standard_count": standard_count,
            "average_value": average_value,
            "notes": notes,
        }
        return summary_block

    def normalize_invoice_primary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes invoice attributes (first copy of duplicated code block)."""
        customer_name = str(payload.get("customer", "guest")).strip().title()
        currency_code = str(payload.get("currency", "USD")).strip().upper()
        region_code = str(payload.get("region", "NA")).strip().upper()
        subtotal_val = max(0.0, float(payload.get("subtotal", 0.0)))
        shipping_val = max(0.0, float(payload.get("shipping", 0.0)))
        grand_total = subtotal_val + shipping_val
        return {
            "customer": customer_name,
            "currency": currency_code,
            "region": region_code,
            "grand_total": grand_total,
        }

    def normalize_invoice_secondary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes credit memo attributes (duplicated 6+ line block)."""
        customer_name = str(payload.get("customer", "guest")).strip().title()
        currency_code = str(payload.get("currency", "USD")).strip().upper()
        region_code = str(payload.get("region", "NA")).strip().upper()
        subtotal_val = max(0.0, float(payload.get("subtotal", 0.0)))
        shipping_val = max(0.0, float(payload.get("shipping", 0.0)))
        grand_total = subtotal_val + shipping_val
        return {
            "customer": customer_name,
            "currency": currency_code,
            "region": region_code,
            "grand_total": grand_total,
        }

    def list_order_ids(self) -> List[str]:
        """Returns identifiers of all tracked orders."""
        return [str(o.get("order_id", "")) for o in self.orders]

    def count_orders(self) -> int:
        """Returns total number of orders."""
        return len(self.orders)

    def clear_orders(self) -> None:
        """Clears cached in-memory orders."""
        self.orders.clear()

    def get_tenant_id(self) -> str:
        """Returns owning tenant identifier."""
        return self.tenant_id

    def export_manifest(self) -> Dict[str, Any]:
        """Exports a lightweight order count manifest."""
        return {"tenant": self.tenant_id, "count": len(self.orders)}


class AuditTrailFormatter:
    """Formats structured audit messages for downstream compliance logs."""

    def __init__(self, service_name: str) -> None:
        """Initializes formatter with owning service identifier."""
        self.service_name = service_name

    def format_event(self, actor: str, action: str, target: str) -> str:
        """Creates a single-line structured audit event string."""
        clean_actor = actor.strip() or "anonymous"
        clean_action = action.strip().upper()
        clean_target = target.strip() or "unknown"
        return f"[{self.service_name}] actor={clean_actor} action={clean_action} target={clean_target}"

    def summarize_events(self, events: List[Dict[str, str]]) -> List[str]:
        """Formats a sequence of event dicts into normalized audit lines."""
        formatted: List[str] = []
        for item in events:
            formatted.append(
                self.format_event(
                    item.get("actor", ""),
                    item.get("action", ""),
                    item.get("target", ""),
                )
            )
        return formatted

