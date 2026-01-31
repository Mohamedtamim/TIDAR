# new_log_detection.py

from typing import Dict, Any
import re
from datetime import datetime, timedelta
from utils.alert_escalator import escalate_alert

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "mid": 2,
    "high": 3,
    "critical": 4,
}

class LogDetector:
    """
    Advanced Rule‑Based Detection Engine for PowerShell / Windows Logs
    with Frequency/Timing Anomaly Detection.
    """

    # for IP frequency detection
    ip_timestamps = {}  # e.g. {"192.168.1.5": [datetime, datetime, ...]}

    def analyze(self, log_entry: Dict[str, Any]) -> bool:
        """
        Analyze a single log entry and update AlertLevel.
        Returns: True if severity >= mid.
        """

        if "AlertLevel" not in log_entry:
            log_entry["AlertLevel"] = "informational"

        # Detection rules
        self._check_execution_policy(log_entry)
        self._check_command_invocation(log_entry)
        self._check_lolbins(log_entry)
        self._check_fileless_behavior(log_entry)
        self._check_obfuscation(log_entry)
        self._check_event_id(log_entry)
        self._check_privilege_escalation(log_entry)
        self._check_persistence(log_entry)
        self._check_lateral_movement(log_entry)
        self._check_network_activity(log_entry)
        self._check_frequency_anomaly(log_entry)
        self._check_anomaly_heuristics(log_entry)

        final_level = log_entry.get("AlertLevel", "informational")
        return SEVERITY_ORDER.get(final_level, 0) >= SEVERITY_ORDER["mid"]

    def _update_severity(self, log_entry: Dict[str, Any], level: str) -> None:
        current = log_entry.get("AlertLevel", "informational").lower()
        if SEVERITY_ORDER.get(level, 0) > SEVERITY_ORDER.get(current, 0):
            log_entry["AlertLevel"] = level

    # ------------------------------------------------------------------
    # Detection Rules
    # ------------------------------------------------------------------

    def _check_execution_policy(self, log_entry):
        policy = str(log_entry.get("ExecutionPolicy", "")).lower()
        if policy in {"bypass", "unrestricted", "silentexecution"}:
            escalate_alert(log_entry, "critical")

    def _check_command_invocation(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        benign_commands = {"ls", "dir", "cd", "pwd", "whoami"}
        suspicious_commands = {"invoke-expression", "iex", "add-mppreference", "disableantispyware"}

        if command.strip() in benign_commands:
            escalate_alert(log_entry, "low")
        if any(cmd in command for cmd in suspicious_commands):
            escalate_alert(log_entry, "high")

    def _check_lolbins(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        lolbins = {"powershell", "pwsh", "certutil", "mshta", "bitsadmin", "wmic", "rundll32", "regsvr32"}
        suspicious_args = {"http", "https", "download", "base64", "-enc", "bypass", "iex"}

        if any(bin in command for bin in lolbins):
            if any(arg in command for arg in suspicious_args):
                escalate_alert(log_entry, "high")
            else:
                escalate_alert(log_entry, "low")

    def _check_fileless_behavior(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        fileless_patterns = {"invoke-expression", "downloadstring", "frombase64string", "reflection.assembly", "memory"}
        if any(p in command for p in fileless_patterns):
            escalate_alert(log_entry, "critical")

    def _check_obfuscation(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        if re.search(r"[a-z0-9+/]{100,}={0,2}", command):
            escalate_alert(log_entry, "high")
        if "`" in command or "^" in command:
            escalate_alert(log_entry, "mid")

    def _check_event_id(self, log_entry):
        event_id = str(log_entry.get("EventID", ""))
        event_map = {
            "4624": "informational",  # Successful logon
            "4625": "mid",            # Failed logon
            "4672": "critical",       # Admin privileges
            "4688": "mid",            # Process creation
            "4697": "high",           # Service installed
            "5145": "mid",            # Network share access
        }
        if event_id in event_map:
            escalate_alert(log_entry, event_map[event_id])

    def _check_privilege_escalation(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        priv_patterns = {"sebackupprivilege", "sedebugprivilege", "add-localgroupmember", "net localgroup administrators"}
        if any(p in command for p in priv_patterns):
            escalate_alert(log_entry, "critical")

    def _check_persistence(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        persistence_patterns = {"schtasks /create", "currentversion\\run", "startup", "new-service", "sc create"}
        if any(p in command for p in persistence_patterns):
            escalate_alert(log_entry, "high")

    def _check_lateral_movement(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        lateral_patterns = {"psexec", "invoke-command", "enter-pssession", "new-pssession", "wmic /node"}
        if any(p in command for p in lateral_patterns):
            escalate_alert(log_entry, "critical")

    def _check_network_activity(self, log_entry):
        command = str(log_entry.get("CommandDescription", "")).lower()
        net_patterns = {"invoke-webrequest", "wget", "curl", "nc ", "netcat", "new-object net.webclient"}
        if any(p in command for p in net_patterns):
            escalate_alert(log_entry, "mid")

    def _check_anomaly_heuristics(self, log_entry):
        score = 0
        command = str(log_entry.get("CommandDescription", ""))
        parent = str(log_entry.get("ParentProcess", "")).lower()

        if len(command) > 300:
            score += 1
        if parent and parent not in {"explorer.exe", "services.exe"}:
            score += 1
        if log_entry.get("ExecutionPolicy", "").lower() == "bypass":
            score += 2
        if score >= 3:
            escalate_alert(log_entry, "high")

    # ------------------------------------------------------------------
    # Frequency / Timing Anomaly Detection
    # ------------------------------------------------------------------

    def _check_frequency_anomaly(self, log_entry):
        """
        Detect same IP performing many actions in short time.
        """
        ip = str(log_entry.get("SourceIP", "")).strip()
        ts = log_entry.get("timestamp")  # assume datetime

        if not ip or not ts:
            return

        # parse timestamp if string
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except Exception:
                return

        now = ts
        window = timedelta(seconds=60)
        threshold = 10

        # init if missing
        if ip not in LogDetector.ip_timestamps:
            LogDetector.ip_timestamps[ip] = []

        # keep only recent timestamps
        LogDetector.ip_timestamps[ip] = [
            t for t in LogDetector.ip_timestamps[ip] if now - t <= window
        ]

        # add current
        LogDetector.ip_timestamps[ip].append(now)

        # if frequency > threshold
        if len(LogDetector.ip_timestamps[ip]) > threshold:
            escalate_alert(log_entry, "high")
