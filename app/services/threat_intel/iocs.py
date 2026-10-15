"""Where each kind of indicator can be looked for in each SIEM, and whether that SIEM can answer at all.

An indicator sweep is only meaningful on a SIEM whose recent events carry the field the indicator would appear in.
Elastic's process metricset has no address, domain or hash fields; Wazuh alerts carry hashes only from file-integrity events and
addresses only for some decoders. When the data is missing the sweep says so instead of reporting "no match".
"""
from typing import Dict, List, Optional, Tuple

# SIEM-side fields, used to build the search and to check the data profile
IOC_FIELDS: Dict[str, Dict[str, List[str]]] = {
    "elastic": {
        "ip": ["source.ip", "destination.ip"],
        "domain": ["dns.question.name", "url.domain", "destination.domain"],
        "sha256": ["file.hash.sha256", "process.hash.sha256"],
    },
    "wazuh": {
        "ip": ["data.srcip", "data.dstip"],
        "domain": [],
        "sha256": ["syscheck.sha256_after"],
    },
}

# the same indicators after the SIEM's event was converted to ECS, used to find which indicator matched
ECS_PATHS: Dict[str, List[str]] = {
    "ip": ["source.ip", "destination.ip"],
    "domain": ["dns.question.name", "url.domain", "destination.domain"],
    "sha256": ["file.hash.sha256", "process.hash.sha256"],
}

KINDS = ("ip", "domain", "sha256")
VULNERABILITY_INDEX = "wazuh-states-vulnerabilities-*"
VULNERABILITY_FIELD = "vulnerability.id"


def fields_for(kind: str, siem_type: str) -> List[str]:
    return IOC_FIELDS.get(siem_type, {}).get(kind, [])


def check_status(kind: str, siem_type: str, profile: Optional[dict]) -> Tuple[str, List[str], List[str]]:
    """(status, fields that carry data, reasons). Status: checkable, blind, archive or unknown."""
    fields = fields_for(kind, siem_type)
    if not fields:
        return "blind", [], [f"{siem_type} has no field that holds {kind} indicators"]
    if profile is None:
        return "unknown", [], ["this SIEM has never been profiled"]
    if not profile.get("recent_docs"):
        return "archive", [], ["no events in the profiled window"]
    measured = profile.get("fields", {})
    unmeasured = [f for f in fields if f not in measured]
    populated = [f for f in fields if measured.get(f, {}).get("present", 0) > 0]
    if populated:
        return "checkable", populated, []
    if unmeasured:
        return "unknown", [], [f"the stored profile never measured {', '.join(unmeasured)}: refresh it"]
    return "blind", [], [f"no recent events carry {', '.join(fields)}"]


def matched_indicators(event: dict, kind: str, wanted: set) -> List[str]:
    """Which of the wanted indicators appear in an ECS event's indicator fields."""
    found = []
    for path in ECS_PATHS[kind]:
        node = event
        for part in path.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        values = node if isinstance(node, list) else [node]
        for value in values:
            if isinstance(value, str) and value.lower() in wanted:
                found.append(value.lower())
    return found
