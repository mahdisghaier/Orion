"""The rule library behind the threat-informed checks and the coverage matrix.

Each rule targets ONE ATT&CK technique and is written to be specific: a daily "found something" that fires on every
ordinary shell would train analysts to ignore it. They use only fields that ORION's field maps know (Image, CommandLine,
TargetFilename), so whether a rule can run on a given SIEM depends on that SIEM's data, which is what the coverage matrix shows.
"""
import re
from typing import Dict, List, Optional

import yaml


def _rule(title: str, category: str, detection: str, tags: List[str]) -> str:
    detection = detection.replace("{", "{{").replace("}", "}}")      # the caller fills {condition} with str.format
    return (f"title: {title}\nstatus: stable\nlogsource:\n  product: linux\n  category: {category}\ndetection:\n{detection}\n"
            f"  condition: {{condition}}\ntags:\n" + "".join(f"  - {t}\n" for t in tags))


def _single(title, detection_field, values, tags, category="process_creation"):
    body = "  selection:\n    " + detection_field + ":\n" + "".join("      - '" + v.replace("'", "''") + "'\n" for v in values).rstrip("\n")
    return _rule(title, category, body, tags).format(condition="selection")


RULES: List[str] = [
    _rule("Reverse shell one-liner", "process_creation",
          "  selection_shell:\n    CommandLine|contains:\n      - '/dev/tcp/'\n      - 'bash -i >&'\n      - 'nc -e '\n      - 'ncat -e '\n      - 'socat exec:'\n"
          "      - 'awk ''BEGIN {system('\n      - 'awk ''BEGIN{system('\n      - '-exec /bin/sh'\n      - '-exec /bin/bash'\n"
          "      - 'chmod +x /tmp/'\n      - 'chmod +x /var/tmp/'\n      - 'chmod +x /dev/shm/'\n"
          "  selection_fetch:\n    CommandLine|contains:\n      - 'curl '\n      - 'wget '\n"
          "  selection_run:\n    CommandLine|contains:\n      - '| sh'\n      - '|sh'\n      - '| bash'\n      - '|bash'",
          ["attack.execution", "attack.t1059.004"]).format(condition="selection_shell or (selection_fetch and selection_run)"),
    _rule("Network discovery tool executed", "process_creation",
          "  selection_tool:\n    Image|endswith:\n      - '/nc'\n      - '/ncat'\n      - '/netcat'\n      - '/nc.openbsd'\n      - '/nmap'\n"
          "  selection_loop:\n    CommandLine|contains|all:\n      - 'for port'\n      - '/dev/tcp/'",
          ["attack.discovery", "attack.t1046"]).format(condition="selection_tool or selection_loop"),
    _rule("Download piped to a shell or saved to a temporary folder", "process_creation",
          "  selection_tool:\n    Image|endswith:\n      - '/curl'\n      - '/wget'\n"
          "  selection_target:\n    CommandLine|contains:\n      - '/tmp/'\n      - '/dev/shm/'\n      - '| sh'\n      - '|sh'\n      - '| bash'\n      - '|bash'\n"
          "  selection_fetch:\n    CommandLine|contains:\n      - 'curl '\n      - 'wget '\n"
          "  selection_run:\n    CommandLine|contains:\n      - 'chmod +x'\n      - '| sh'\n      - '|sh'\n      - '| bash'\n      - '|bash'",
          ["attack.command_and_control", "attack.t1105"]).format(condition="(selection_tool and selection_target) or (selection_fetch and selection_run)"),
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
    _rule("Cron table edited", "process_creation",
          "  selection_tool:\n    Image|endswith:\n      - '/crontab'\n"
          "  selection_file:\n    CommandLine|contains:\n      - '/etc/cron.d/'\n      - '/etc/cron.daily/'\n      - '/etc/cron.hourly/'\n      - '/var/spool/cron/'",
          ["attack.persistence", "attack.t1053.003"]).format(condition="selection_tool or selection_file"),
    _single("Setuid or setgid bit set", "CommandLine|contains",
            ["chmod u+s", "chmod u+xs", "chmod g+s", "chmod g+xs", "chmod +s", "chmod 4755", "chmod 4777", "chmod 6755",
             "chmod 2755", "-perm -4000", "-perm -2000", "-perm -u=s", "-perm /4000"],
            ["attack.privilege_escalation", "attack.t1548.001"]),
    _single("Shadow password file accessed", "CommandLine|contains", ["/etc/shadow"],
            ["attack.credential_access", "attack.t1003.008"]),
    _single("Critical system file changed", "TargetFilename|contains",
            ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/crontab"],
            ["attack.persistence", "attack.t1565.001"], category="file_event"),
    _single("Network connections listed", "CommandLine|contains",
            ["netstat ", "ss -tulnp", "ss -antp", "ss -plnt", "lsof -i"],
            ["attack.discovery", "attack.t1049"]),
    _single("Network configuration listed", "CommandLine|contains",
            ["ifconfig", "ip addr", "ip route", "ip a ", "arp -a", "cat /etc/resolv.conf"],
            ["attack.discovery", "attack.t1016"]),
    _rule("System information gathered", "process_creation",
          "  selection_cmd:\n    CommandLine|contains:\n      - 'uname -a'\n      - 'cat /etc/os-release'\n      - 'cat /etc/issue'\n      - 'lscpu'\n      - 'dmidecode'\n      - 'hostnamectl'\n"
          "  selection_tool:\n    Image|endswith:\n      - '/hostname'\n      - '/lsmod'",
          ["attack.discovery", "attack.t1082"]).format(condition="selection_cmd or selection_tool"),
    _single("Accounts enumerated", "CommandLine|contains",
            ["/etc/passwd", "getent passwd", "lastlog", "/etc/group"],
            ["attack.discovery", "attack.t1087"]),
    _single("Encoded content decoded on the command line", "CommandLine|contains",
            ["base64 -d", "base64 --decode", "openssl enc -d", "xxd -r"],
            ["attack.defense_evasion", "attack.t1140"]),
    _rule("Decoded content piped into a shell", "process_creation",
          "  selection_decode:\n    CommandLine|contains:\n      - 'base64 -d'\n      - 'base64 --decode'\n      - 'xxd -r'\n"
          "  selection_shell:\n    CommandLine|contains:\n      - '| sh'\n      - '|sh'\n      - '| bash'\n      - '|bash'",
          ["attack.defense_evasion", "attack.t1027.010"]).format(condition="selection_decode and selection_shell"),
    _single("Python used for a socket or terminal spawn", "CommandLine|contains",
            ["import socket", "import pty", "pty.spawn", "os.system(", "subprocess.call("],
            ["attack.execution", "attack.t1059.006"]),
    _rule("Archive written to a staging folder", "process_creation",
          "  selection_tool:\n    Image|endswith:\n      - '/tar'\n      - '/zip'\n      - '/7z'\n"
          "  selection_target:\n    CommandLine|contains:\n      - ' /tmp/'\n      - ' /dev/shm/'\n      - ' /var/tmp/'",
          ["attack.collection", "attack.t1074.001"]).format(condition="selection_tool and selection_target"),
    _single("Tunnel or proxy set up", "CommandLine|contains",
            ["ssh -D", "ssh -R", "ssh -L", "socat tcp-listen", "chisel ", "proxychains"],
            ["attack.command_and_control", "attack.t1090"]),
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
