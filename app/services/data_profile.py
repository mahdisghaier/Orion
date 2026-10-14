"""What a SIEM connection can actually see: volume, time coverage and field population.

A Sigma rule can be fully translatable and still blind on a given SIEM: the field it needs is
mapped but no event carries it (Metricbeat's process metricset has no parent executable, Wazuh
alerts have no process fields). A hunt that returns "0 hits" there means "could not look", not
"clean". The profile makes that visible, to analysts, to the hunt runner and to the AI agent.

Profiles describe the last `window_days` of data; first/last event cover everything.
"""
from typing import Dict, Iterable, List, Optional

from app.services.sigma_engine import _ECS_FIELD_MAPPING, _WAZUH_FIELD_MAPPING

SIEM_FIELD_MAPS: Dict[str, dict] = {
    "elastic": _ECS_FIELD_MAPPING,
    "wazuh": _WAZUH_FIELD_MAPPING,
}

# Fields profiled beyond those a Sigma mapping targets (context for analysts and the AI agent)
# [explain] A few extra details worth measuring besides the ones the rule translation needs.
_EXTRA_FIELDS = {
    "elastic": ["process.name", "event.action", "source.ip", "destination.ip"],
    "wazuh": ["data.dstuser", "rule.id", "rule.level", "rule.mitre.id"],
}

# What "kinds of events" means per SIEM: the field to count top values of
TOP_FIELD = {"elastic": "event.dataset", "wazuh": "rule.description"}

DEFAULT_WINDOW_DAYS = 7


def _targets(sigma_field: str, siem_type: str) -> List[str]:
    target = SIEM_FIELD_MAPS.get(siem_type, {}).get(sigma_field)
    if target is None:
        return []
    return list(target) if isinstance(target, (list, tuple)) else [target]


# [explain] Which details to measure for a SIEM: every field a rule can be translated into, so the check can never drift from the translation.
def profile_fields(siem_type: str) -> List[str]:
    """Fields to profile: every field a Sigma mapping targets, plus a few extras. Stays in sync with the maps."""
    fields = {t for sf in SIEM_FIELD_MAPS.get(siem_type, {}) for t in _targets(sf, siem_type)}
    fields.update(_EXTRA_FIELDS.get(siem_type, []))
    return sorted(fields)


# [explain] Packs the raw counts into the check-up document: how many events, first/last time, and what percent carry each field.
def build_profile(siem_type: str, window_days: int, total_docs: int, recent_docs: int,
                  earliest: Optional[str], latest: Optional[str],
                  field_counts: Dict[str, int], top: Iterable[tuple]) -> dict:
    """Normalise raw aggregation results into the stored profile document."""
    return {
        "siem_type": siem_type,
        "window_days": window_days,
        "total_docs": total_docs,
        "recent_docs": recent_docs,
        "earliest": earliest,
        "latest": latest,
        "fields": {
            f: {"present": n, "pct": round(100.0 * n / recent_docs, 1) if recent_docs else 0.0}
            for f, n in sorted(field_counts.items())
        },
        "top_label": TOP_FIELD.get(siem_type),
        "top": [{"value": str(k), "count": c} for k, c in top],
    }


# [explain] A blind spot = a detail the rule needs but NO recent event carries.
# [explain] A SIEM with no recent events at all (an archive) is never judged, it may still hold older data.
def blind_spots(sigma_fields: Iterable[str], siem_type: str, profile: Optional[dict]) -> List[str]:
    """Rule fields whose SIEM field has NO events in the profiled window, e.g. "ParentImage -> process.parent.executable".

    Only judged when the SIEM has recent data: a silent SIEM (an archive, like the August demo
    index) may legitimately hold older events, so silence alone never blocks a hunt.
    Fields the profile did not measure are not judged.
    """
    if not profile or not profile.get("recent_docs"):
        return []
    measured = profile.get("fields", {})
    blind = []
    for sigma_field in sorted(set(sigma_fields)):
        targets = _targets(sigma_field, siem_type)
        stats = [measured[t] for t in targets if t in measured]
        if targets and len(stats) == len(targets) and all(s["present"] == 0 for s in stats):
            blind.append(f"{sigma_field} -> {' / '.join(targets)}")
    return blind
