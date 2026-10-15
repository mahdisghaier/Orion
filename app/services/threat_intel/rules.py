"""The rule library behind the threat-informed checks and the coverage matrix.

Each rule targets ONE ATT&CK technique and is written to be specific: a daily "found something" that fires on every
ordinary shell would train analysts to ignore it. They use only fields that ORION's field maps know (Image, CommandLine,
TargetFilename), so whether a rule can run on a given SIEM depends on that SIEM's data, which is what the coverage matrix shows.
"""
import re
from typing import Dict, List, Optional

import yaml


def _rule(title: str, category: str, detection: str, tags: List[str]) -> str:
    return (f"title: {title}\nstatus: stable\nlogsource:\n  product: linux\n  category: {category}\ndetection:\n{detection}\n"
            f"  condition: {{condition}}\ntags:\n" + "".join(f"  - {t}\n" for t in tags))


def _single(title, detection_field, values, tags, category="process_creation"):
    body = "  selection:\n    " + detection_field + ":\n" + "".join(f"      - '{v}'\n" for v in values).rstrip("\n")
    return _rule(title, category, body, tags).format(condition="selection")


RULES: List[str] = [
    _single("Reverse shell one-liner", "CommandLine|contains",
            ["/dev/tcp/", "bash -i >&", "nc -e ", "ncat -e ", "socat exec:"],
            ["attack.execution", "attack.t1059.004"]),
    _single("Network discovery tool executed", "Image|endswith",
            ["/nc", "/ncat", "/netcat", "/nc.openbsd", "/nmap"],
            ["attack.discovery", "attack.t1046"]),
    _rule("Download piped to a shell or saved to a temporary folder", "process_creation",
          "  selection_tool:\n    Image|endswith:\n      - '/curl'\n      - '/wget'\n"
          "  selection_target:\n    CommandLine|contains:\n      - '/tmp/'\n      - '/dev/shm/'\n      - '| sh'\n      - '|sh'\n      - '| bash'\n      - '|bash'",
          ["attack.command_and_control", "attack.t1105"]).format(condition="selection_tool and selection_target"),
    _single("Shell history cleared", "CommandLine|contains",
            ["history -c", "unset HISTFILE", "HISTFILE=/dev/null", "HISTSIZE=0", "rm ~/.bash_history", "> ~/.bash_history"],
            ["attack.defense_evasion", "attack.t1070.003"]),
    _single("System logs removed or truncated", "CommandLine|contains",
            ["rm /var/log", "truncate -s 0 /var/log", "> /var/log/", "shred /var/log"],
            ["attack.defense_evasion", "attack.t1070.002"]),
    _single("Security tooling stopped or disabled", "CommandLine|contains",
            ["systemctl stop auditd", "systemctl disable auditd", "service auditd stop", "systemctl stop wazuh-agent",
             "systemctl stop falco", "setenforce 0", "systemctl stop apparmor"],
            ["attack.defense_evasion", "attack.t1562.001"]),
    _single("Local account created", "Image|endswith", ["/useradd", "/adduser"],
            ["attack.persistence", "attack.t1136.001"]),
    _single("Cron table edited", "Image|endswith", ["/crontab"],
            ["attack.persistence", "attack.t1053.003"]),
    _single("Setuid or setgid bit set", "CommandLine|contains",
            ["chmod u+s", "chmod +s", "chmod 4755", "chmod 4777", "chmod 6755"],
            ["attack.privilege_escalation", "attack.t1548.001"]),
    _single("Shadow password file accessed", "CommandLine|contains", ["/etc/shadow"],
            ["attack.credential_access", "attack.t1003.008"]),
    _single("Critical system file changed", "TargetFilename|contains",
            ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab"],
            ["attack.persistence", "attack.t1565.001"], category="file_event"),
]


def technique_of(rule_yaml: str) -> Optional[str]:
    """The ATT&CK technique id a rule is tagged with (T1059.004), or None."""
    for tag in (yaml.safe_load(rule_yaml) or {}).get("tags", []):
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.I)
        if match:
            return match.group(1).upper()
    return None


def tactic_of(rule_yaml: str) -> Optional[str]:
    for tag in (yaml.safe_load(rule_yaml) or {}).get("tags", []):
        name = str(tag).removeprefix("attack.")
        if tag.startswith("attack.") and not re.fullmatch(r"t\d{4}(\.\d{3})?", name, re.I):
            return name
    return None


def title_of(rule_yaml: str) -> str:
    return str((yaml.safe_load(rule_yaml) or {}).get("title", "rule"))


def library() -> List[Dict[str, str]]:
    """The rules as records, one per technique."""
    return [{"technique": technique_of(r), "tactic": tactic_of(r), "title": title_of(r), "yaml": r} for r in RULES]


def rules_for(technique_id: str) -> List[Dict[str, str]]:
    """Rules that cover a technique: an exact match, or a rule for the parent technique."""
    wanted = technique_id.upper()
    parent = wanted.split(".")[0]
    return [r for r in library() if r["technique"] in (wanted, parent)]
