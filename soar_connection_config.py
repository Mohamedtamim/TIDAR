"""
ADDED FOR SOAR CONNECTION SETTINGS

In-memory runtime config for SOAR executor connection (IP, username, password).
Used by soar_executor_bridge when creating the shared PersistentSSHExecutor.
Password is never logged or persisted to disk.
"""

from __future__ import annotations

import threading
from typing import Tuple

# ADDED FOR SOAR CONNECTION SETTINGS: Initialize from connection_init defaults
def _load_defaults() -> dict:
    try:
        from utils.connection_init import TARGET_IP, USERNAME, PASSWORD
        return {"ip": TARGET_IP, "username": USERNAME, "password": PASSWORD}
    except Exception:
        return {"ip": "0.0.0.0", "username": "DeviceName", "password": "000"}

_settings: dict = _load_defaults()
_lock = threading.Lock()


def get_connection_settings() -> Tuple[str, str, str]:
    """
    ADDED FOR SOAR CONNECTION SETTINGS.
    Returns (ip, username, password). Thread-safe. No logging.
    """
    with _lock:
        return (_settings["ip"], _settings["username"], _settings["password"])


def update_connection_settings(ip: str, username: str, password: str) -> None:
    """
    ADDED FOR SOAR CONNECTION SETTINGS.
    Update runtime settings. Thread-safe. Never logs password.
    """
    with _lock:
        _settings["ip"] = ip.strip()
        _settings["username"] = username.strip()
        _settings["password"] = password


def get_target_ip() -> str:
    """ADDED FOR SOAR CONNECTION SETTINGS. Convenience for event payloads."""
    return get_connection_settings()[0]


def get_username() -> str:
    """ADDED FOR SOAR CONNECTION SETTINGS. Convenience for event payloads."""
    return get_connection_settings()[1]
