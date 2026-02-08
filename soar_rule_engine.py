"""
SOAR Rule Engine

Loads YAML rules and maps extracted features (ip, alert_level) to SSH commands.
No detection logic - only rule matching.

ADDED FOR YAML PLAYBOOKS: Load from config/soar_rules.yaml and config/playbooks/*.yml
"""

from pathlib import Path
from typing import Dict, Any, Optional, List

# Optional YAML; fallback to empty rules if not installed
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from utils.soar_event_bus import publish_event


def _get_rules_path() -> Path:
    """Resolve config path relative to project root."""
    base = Path(__file__).resolve().parent.parent
    return base / "config" / "soar_rules.yaml"


def _get_playbooks_dir() -> Path:
    """ADDED FOR YAML PLAYBOOKS: Playbooks folder."""
    base = Path(__file__).resolve().parent.parent
    return base / "config" / "playbooks"


def load_rules(rules_path: Optional[Path] = None) -> list:
    """
    Load SOAR rules from YAML file.
    Returns empty list if file missing or YAML not installed.
    """
    path = rules_path or _get_rules_path()
    if not path.exists() or not _HAS_YAML:
        return _load_playbooks()

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        rules = data.get("rules") if isinstance(data, dict) else []
        rules_list = rules if isinstance(rules, list) else []
        playbooks = _load_playbooks()
        all_rules = rules_list + playbooks
        publish_event(
            "rules_loaded",
            {
                "rule_count": len(all_rules),
                "path": str(path),
            },
            source="rule_engine",
        )
        return all_rules
    except Exception:
        return _load_playbooks()


def _load_playbooks() -> List[Dict]:
    """ADDED FOR YAML PLAYBOOKS: Load rules from config/playbooks/*.yml"""
    if not _HAS_YAML:
        return []
    playbooks_dir = _get_playbooks_dir()
    if not playbooks_dir.exists() or not playbooks_dir.is_dir():
        return []
    rules = []
    for p in sorted(playbooks_dir.glob("*.yml")):
        try:
            with open(p, "r") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            items = data.get("rules") or data.get("playbook") or []
            if isinstance(items, dict):
                items = [items]
            for r in items:
                if isinstance(r, dict) and r.get("enabled", True):
                    rules.append(r)
        except Exception:
            pass
    return rules


def _normalize_level(level: Any) -> str:
    """Normalize alert_level for case-insensitive matching."""
    if level is None:
        return ""
    return str(level).lower().strip()


def _match_rule(rule: Dict[str, Any], features: Dict[str, Any]) -> bool:
    """
    Check if features match a single rule.
    ADDED FOR YAML PLAYBOOKS: Skip rules with enabled=false.
    Supports: alert_level, event_id (optional), ip (optional).
    """
    if rule.get("enabled") is False:
        return False
    levels = rule.get("alert_level")
    if levels is not None:
        if isinstance(levels, str):
            levels = [levels]
        feat_level = _normalize_level(features.get("alert_level"))
        if feat_level not in [str(l).lower() for l in levels]:
            return False

    event_ids = rule.get("event_id")
    if event_ids is not None:
        if isinstance(event_ids, (int, str)):
            event_ids = [event_ids]
        feat_eid = features.get("event_id")
        if feat_eid is None:
            return False
        if int(feat_eid) not in [int(e) for e in event_ids]:
            return False

    return True


def decide_action_from_rules(features: Dict[str, Any], rules: Optional[list] = None) -> Optional[str]:
    """
    Match features against rules and return the SSH command to execute.
    First matching rule wins.

    Args:
        features: Dict from extract_soar_features, e.g. {ip, alert_level, event_id}.
        rules: Optional list of rules; if None, loads from config.

    Returns:
        SSH command string with {ip} substituted, or None for no_action.
    """
    if not features or not isinstance(features, dict):
        return None

    if rules is None:
        rules = load_rules()

    ip = str(features.get("ip") or "unknown")

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not _match_rule(rule, features):
            continue

        action = rule.get("action", "")
        if action == "no_action":
            return None

        cmd = rule.get("command")
        if cmd and isinstance(cmd, str):
            return cmd.replace("{ip}", ip)

        return None

    return None
