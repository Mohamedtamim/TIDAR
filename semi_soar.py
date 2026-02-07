# SOAR execution: YAML rules + SSH. Uses shared PersistentSSHExecutor.
# ADDED FOR SOAR SIEM-ALERT INTEGRATION: Consumes alerts from SIEM Alert only.
# ADDED FOR YAML PLAYBOOKS: 5-second delay before auto actions, manual override cancels.

import threading
from utils.soar_connection_config import get_target_ip, get_username  # ADDED FOR SOAR CONNECTION SETTINGS
from utils.soar_event_bus import publish_event
from utils.soar_executor_bridge import get_executor
from utils.soar_integration import get_next_features, install_alert_handler
from utils.soar_rule_engine import decide_action_from_rules
from utils.soar_alert_store import (
    create_case,
    update_case,
    register_pending_timer,
    unregister_pending_timer,
)

_AUTO_DELAY_SECONDS = 5


def _execute_after_delay(alert_id: str, features: dict, cancel_flag: list) -> None:
    """
    ADDED FOR SOAR SIEM-ALERT INTEGRATION: Called after 5s delay.
    Cancels if cancel_flag[0] is True (manual override).
    """
    unregister_pending_timer(alert_id)
    if cancel_flag[0]:
        return
    update_case(alert_id, status="Executing")
    _run_automated_action(alert_id, features)


def _run_automated_action(alert_id: str, features: dict) -> None:
    """Execute matched playbook action. ADDED FOR SOAR SIEM-ALERT INTEGRATION."""
    try:
        executor = get_executor()
        command = decide_action_from_rules(features)
        publish_event(
            "automation_decision",
            {"command": command, "features": dict(features), "alert_id": alert_id},
            source="automation",
        )
        if command:
            publish_event(
                "automation_command_dispatch",
                {"command": command, "alert_id": alert_id},
                source="automation",
            )
            result = executor.send_command(command)
            success = result.get("exit_code") == 0
            update_case(
                alert_id,
                status="Completed",
                message="Success" if success else "Failed",
                result=result,
            )
            publish_event(
                "automation_command_result",
                {
                    "command": command,
                    "exit_code": result.get("exit_code"),
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                    "success": success,
                    "alert_id": alert_id,
                },
                source="automation",
            )
        else:
            update_case(alert_id, status="Completed", message="No action required")
            publish_event(
                "automation_no_action",
                {
                    "alert_level": features.get("alert_level"),
                    "ip": features.get("ip"),
                    "alert_id": alert_id,
                },
                source="automation",
            )
    except Exception as exc:
        update_case(alert_id, status="Completed", message=f"Error: {exc}", result={"error": str(exc)})
        publish_event(
            "automation_error",
            {"error": str(exc), "alert_id": alert_id},
            source="automation",
        )


def soar_execution_starter():
    """
    SOAR execution loop: pull from SIEM Alert queue, 5s delay, then execute.
    ADDED FOR SOAR SIEM-ALERT INTEGRATION: Consumes ingest_siem_alert only.
    ADDED FOR YAML PLAYBOOKS: 5-second delay, manual override cancels auto.
    SSH connection is non-blocking: app starts even if target is unreachable.
    """
    install_alert_handler()
    try:
        executor = get_executor()
        publish_event(
            "automation_executor_ready",
            {"target": get_target_ip(), "username": get_username()},
            source="automation",
        )
    except Exception as e:
        print(f"[!] SOAR executor init failed: {e} (SOAR will run without remote execution)")
        publish_event(
            "automation_executor_ready",
            {"target": get_target_ip(), "error": str(e)},
            source="automation",
        )

    print("[*] SOAR logic engine started (SIEM Alert -> 5s delay -> YAML playbooks)")

    try:
        while True:
            item = get_next_features(timeout=0.5)
            if not item:
                continue

            features = item.get("features") or item
            raw_log = item.get("raw_log")
            if isinstance(features, dict) and "alert_level" not in features:
                features = item if isinstance(item, dict) else {}
            if not features:
                continue

            alert_id = create_case(features, raw_log)
            severity = str(features.get("alert_level", "unknown")).lower()
            summary = features.get("ip", "N/A") or features.get("event_id", "N/A")

            publish_event(
                "automation_feature_ready",
                {"features": dict(features), "alert_id": alert_id},
                source="automation",
            )

            msg = f"New {severity} alert received: {summary}. Auto-response will run in {_AUTO_DELAY_SECONDS} seconds unless cancelled."
            publish_event(
                "automation_alert_pending",
                {
                    "alert_id": alert_id,
                    "severity": severity,
                    "message": msg,
                    "delay_seconds": _AUTO_DELAY_SECONDS,
                },
                source="automation",
            )
            print(f"[SOAR] {msg}")

            cancel_flag = [False]
            timer = threading.Timer(
                _AUTO_DELAY_SECONDS,
                _execute_after_delay,
                args=[alert_id, features, cancel_flag],
            )
            register_pending_timer(alert_id, timer, cancel_flag)
            timer.start()

    except KeyboardInterrupt:
        publish_event("automation_stopped", source="automation", payload={})
    except Exception as exc:
        publish_event(
            "automation_error",
            {"error": str(exc)},
            source="automation",
        )
        raise
