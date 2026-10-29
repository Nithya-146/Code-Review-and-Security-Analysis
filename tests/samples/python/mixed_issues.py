"""
Mixed Quality and Security Issues Sample.
Contains both code quality smells and security vulnerabilities.
"""

import requests


def process_user_file_request(
    file_id: str,
    base_folder: str,
    tenant_id: str,
    user_token: str,
    operation_mode: str,
    extra_flags: dict
) -> str:
    """Too many parameters (>5) and path traversal vulnerability."""
    target_path = base_folder + "/" + file_id
    with open(target_path, "r") as f:
        return f.read()


def sync_remote_endpoint(url: str) -> None:
    """SSRF/Insecure TLS with verify=False and bare except clause."""
    try:
        response = requests.get(url, verify=False)
        print(response.status_code)
    except:
        print("Network error")
