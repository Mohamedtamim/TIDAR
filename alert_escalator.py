# alert_escalator.py
from typing import Dict, Any

# Alert severity priority (higher = more dangerous)
ALERT_PRIORITY = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "suspicious": 3,
    "high": 4,
    "critical": 5
}


def escalate_alert(log_entry: Dict[str, Any], new_level: str) -> None:
    """
    Escalate AlertLevel if new_level is higher than current level.
    Never downgrades.

    Args:
        log_entry: formatted log record
        new_level: requested severity (high / critical / etc.)
    """
    current_level = str(log_entry.get("AlertLevel", "")).lower()
    new_level = new_level.lower()

    current_priority = ALERT_PRIORITY.get(current_level, 0)
    new_priority = ALERT_PRIORITY.get(new_level, 0)

    if new_priority > current_priority:
        log_entry["AlertLevel"] = new_level.capitalize()
