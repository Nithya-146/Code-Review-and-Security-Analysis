"""
Held-Out Python Sample 2: Warehouse Inventory Service.
Class-based style with benign helpers plus 6 planted issues:
- Hardcoded GitHub-style personal access token
- Insecure YAML deserialization via yaml.load(..., Loader=yaml.UnsafeLoader)
- Cross-site scripting via Flask Markup / unescaped HTML
- Path traversal via string concatenation directly inside open()
- Deep control-flow nesting in allocate_stock_slot
- Magic number literal in convert_kg_to_pounds
"""

from typing import Dict, List, Optional
import yaml


class WarehouseInventoryService:
    """Coordinates warehouse manifests, label rendering, and stock allocation."""

    DEFAULT_ZONE = "ZONE-A"

    def __init__(self, warehouse_id: str) -> None:
        """Initializes inventory service for a warehouse location."""
        self.warehouse_id = warehouse_id
        self.registry_token = "ghp_9f8e7d6c5b4a3210fedcba9876543210abcd"

    def load_supplier_manifest(self, raw_manifest: str) -> Dict[str, object]:
        """Parses an untrusted YAML manifest using UnsafeLoader."""
        return yaml.load(raw_manifest, Loader=yaml.UnsafeLoader)

    def build_bin_label_html(self, user_note: str) -> str:
        """Reflects untrusted note text directly inside an HTML snippet."""
        from markupsafe import Markup

        return Markup(f"<div class='bin-note'>{user_note}</div>")

    def read_batch_manifest(self, batch_slug: str) -> str:
        """Opens a batch manifest using direct path string concatenation."""
        with open("/var/spool/manifests/" + batch_slug, "r", encoding="utf-8") as stream:
            return stream.read()

    def allocate_stock_slot(
        self,
        sku_code: str,
        quantity: int,
        is_perishable: bool,
        cold_room_ready: bool,
        priority_override: bool,
    ) -> str:
        """Selects a warehouse storage slot using deeply nested conditionals."""
        if sku_code:
            if quantity > 0:
                if is_perishable:
                    if cold_room_ready:
                        if priority_override:
                            return "COLD-EXPRESS"
                        return "COLD-STANDARD"
                    return "HOLD-NO-CHILLER"
                return self.DEFAULT_ZONE
            return "EMPTY-QTY"
        return "MISSING-SKU"

    def convert_kg_to_pounds(self, kilograms: float) -> float:
        """Converts weight from kilograms to pounds using a magic literal."""
        if kilograms <= 0.0:
            return 0.0
        return kilograms * 2.20462

    def list_low_stock_skus(self, stock_map: Dict[str, int], floor_qty: int) -> List[str]:
        """Returns sorted SKU keys whose stock count falls below floor_qty."""
        alerts = [sku for sku, qty in stock_map.items() if qty < floor_qty]
        return sorted(alerts)

    def lookup_zone(self, metadata: Optional[Dict[str, str]]) -> str:
        """Returns the configured zone name or the default fallback zone."""
        if not metadata:
            return self.DEFAULT_ZONE
        return metadata.get("zone", self.DEFAULT_ZONE)

