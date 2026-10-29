"""
Clean, Production-Grade Python Module.
Adheres strictly to PEP 8, modular architecture, and security best practices.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE: int = 20
MAX_ITEMS_PER_PAGE: int = 100


class UserProfileService:
    """Service managing customer account profiles and preferences."""

    def __init__(self, service_region: str = "us-east") -> None:
        """Initializes service with target regional endpoint."""
        self.service_region = service_region
        self.cached_profiles: Dict[str, Dict[str, str]] = {}

    def retrieve_profile(self, user_id: str) -> Optional[Dict[str, str]]:
        """Retrieves user profile information by unique identifier."""
        if not user_id.strip():
            logger.warning("Empty user identifier provided.")
            return None
        return self.cached_profiles.get(user_id)

    def store_profile(self, user_id: str, profile_data: Dict[str, str]) -> bool:
        """Stores or updates customer profile data in cache."""
        if not user_id.strip() or not profile_data:
            return False
        self.cached_profiles[user_id] = profile_data
        return True


def format_user_display_name(first_name: str, last_name: str) -> str:
    """Formats full customer name for presentation."""
    cleaned_first = first_name.strip()
    cleaned_last = last_name.strip()
    return f"{cleaned_first} {cleaned_last}".strip()
