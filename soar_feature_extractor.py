"""
SOAR Feature Extractor

Extracts {ip, alert_level} from logs already flagged by log_detection.
No detection logic - only extraction. Output is a simple dict for SOAR decision layer.
"""

from typing import Dict, Any, Optional

# IP field candidates (log_formatter uses HostIP, log_detection uses SourceIP)
_IP_FIELDS = ("SourceIP", "HostIP", "source_ip", "host_ip", "Host_IP", "SourceIp", "HostIp")
# Alert level field candidates (LogDetector sets AlertLevel)
_ALERT_FIELDS = ("AlertLevel", "alert_level", "severity", "level")


def extract_soar_features(flagged_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract SOAR-relevant features from a log already flagged by log_detection.

    Args:
        flagged_log: Log entry that has been analyzed and flagged (is_alert=True).
                     Must contain AlertLevel; IP may be in SourceIP or HostIP.

    Returns:
        Dict with keys: ip (str), alert_level (str).
        Optional extras for YAML conditions: severity, event_id, command.
        Returns None if alert_level cannot be extracted.
    """
    if not flagged_log or not isinstance(flagged_log, dict):
        return None

    alert_level = None
    for field in _ALERT_FIELDS:
        val = flagged_log.get(field)
        if val is not None and str(val).strip():
            alert_level = str(val).strip()
            break

    if not alert_level:
        return None

    ip = ""
    for field in _IP_FIELDS:
        val = flagged_log.get(field)
        if val is not None and str(val).strip() and str(val) not in ("N/A", "127.0.0.1", ""):
            ip = str(val).strip()
            break

    out: Dict[str, Any] = {
        "ip": ip or "unknown",
        "alert_level": alert_level,
    }

    # Optional fields for YAML rule conditions (no extra detection logic)
    if "EventID" in flagged_log:
        out["event_id"] = flagged_log.get("EventID")
    if "CommandLine" in flagged_log or "CommandDescription" in flagged_log:
        cmd = flagged_log.get("CommandLine") or flagged_log.get("CommandDescription") or ""
        out["command"] = str(cmd)[:512]  # limit length
    if "ComputerName" in flagged_log:
        out["hostname"] = str(flagged_log.get("ComputerName", ""))

    return out
