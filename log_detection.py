# log_detection.py

from typing import Dict, Any
from utils.alert_escalator import escalate_alert


class LogDetector:
    """
    Core detection engine for TDARE
    """

    def analyze(self, log_entry: Dict[str, Any]) -> bool:
        """
        Analyze log entry and escalate AlertLevel if needed.

        Returns:
            True if log is suspicious / high / critical
        """
        self._check_execution_policy(log_entry)
        self._check_command_keywords(log_entry)
        self._check_event_id(log_entry)

        # Final decision based on AlertLevel
        alert = str(log_entry.get("AlertLevel", "")).lower()
        return alert in {"suspicious", "high", "critical"}

    # -----------------------------
    # Detection rules
    # -----------------------------

    def _check_execution_policy(self, log_entry: Dict[str, Any]) -> None:
        policy = str(log_entry.get("ExecutionPolicy", "")).lower()

        if policy in {"bypass", "silentexecution"}:
            # PowerShell bypass = critical
            escalate_alert(log_entry, "critical")

    def _check_command_keywords(self, log_entry: Dict[str, Any]) -> None:
        # I can make a function like this to normalize the normal logs
        command = str(log_entry.get("CommandDescription", "")).lower()

        suspicious_keywords = {
            "malware", "trojan", "ransomware",
            "brute force", "sql injection",
            "xss", "command injection",
            "exploit", "breach"
        }

        if any(keyword in command for keyword in suspicious_keywords):
            escalate_alert(log_entry, "high")

    def _check_event_id(self, log_entry: Dict[str, Any]) -> None:
        event_id = str(log_entry.get("EventID", ""))

        suspicious_event_ids = {
            "4625",  # Failed logon
            "4672",  # Admin privileges assigned
            "4688",  # Process creation
            "5145",  # Network share access
            "5156",  # Firewall rule change
        }

        if event_id in suspicious_event_ids:
            escalate_alert(log_entry, "high")
