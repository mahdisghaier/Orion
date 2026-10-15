"""Which rule can run on which SIEM, and why not: the coverage matrix.

A rule is only worth hunting with where the SIEM has the data it needs. This module classifies each (rule, SIEM) pair:

  runnable      a field mapping exists and recent events carry every field the rule needs
  blind         the mapping exists but NO recent event carries a needed field (the rule would return nothing for the wrong reason)
  not_runnable  no field mapping for something the rule needs, or no query could be generated
  archive       the SIEM has no events in the profiled window (an archive), so it says nothing about current activity
  unknown       the SIEM was never profiled, or its stored profile does not measure a field the rule needs (take a new profile)
"""
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SIEMConnection, SIEMProfile
from app.services.data_profile import blind_spots, unmeasured_fields
from app.services.sigma_engine import SIEM_FIELD_PROFILES, convert_sigma_rule, rule_fields, unmapped_fields
from app.services.threat_intel.rules import library

QUERY_KEY = {"elastic": "eql", "wazuh": "lucene", "sentinel": "kql"}
LIVE_STATUSES = {"runnable"}


def rule_status(rule_yaml: str, siem_type: str, profile: Optional[dict]) -> Tuple[str, List[str]]:
    if siem_type not in SIEM_FIELD_PROFILES:
        return "not_runnable", [f"ORION has no field map for {siem_type} SIEMs"]
    missing = unmapped_fields(rule_yaml, siem_type)
    if missing:
        return "not_runnable", [f"no field mapping for {', '.join(missing)}"]
    if not convert_sigma_rule(rule_yaml).get(QUERY_KEY.get(siem_type, "")):
        return "not_runnable", ["no query could be generated for this SIEM"]
    if profile is None:
        return "unknown", ["this SIEM has never been profiled"]
    if not profile.get("recent_docs"):
        return "archive", ["no events in the profiled window"]
    used = rule_fields(rule_yaml)
    stale = unmeasured_fields(used, siem_type, profile)
    if stale:
        return "unknown", [f"the stored profile never measured {', '.join(stale)}: refresh it"]
    blind = blind_spots(used, siem_type, profile)
    if blind:
        return "blind", [f"no recent events carry {b}" for b in blind]
    return "runnable", []


async def active_connections_with_profiles(db: AsyncSession) -> List[dict]:
    connections = (await db.execute(
        select(SIEMConnection).where(SIEMConnection.is_active.is_(True)).order_by(SIEMConnection.created_at)
    )).scalars().all()
    profiles = {
        row.siem_connection_id: row.profile
        for row in (await db.execute(select(SIEMProfile))).scalars().all()
    }
    return [{"id": c.id, "name": c.name, "type": c.type, "profile": profiles.get(c.id)} for c in connections]


def matrix(connections: List[dict]) -> dict:
    """Pure: rows of (rule, per-connection status) plus a summary. `connections` come from active_connections_with_profiles."""
    rows = []
    for rule in library():
        cells = []
        for conn in connections:
            status, reasons = rule_status(rule["yaml"], conn["type"], conn["profile"])
            cells.append({"connection": conn["name"], "siem_type": conn["type"], "status": status, "reasons": reasons})
        rows.append({"technique": rule["technique"], "tactic": rule["tactic"], "title": rule["title"], "cells": cells})
    summary: Dict[str, int] = {}
    for row in rows:
        for cell in row["cells"]:
            summary[cell["status"]] = summary.get(cell["status"], 0) + 1
    runnable_somewhere = sum(1 for row in rows if any(c["status"] == "runnable" for c in row["cells"]))
    return {
        "connections": [{"name": c["name"], "type": c["type"]} for c in connections],
        "rows": rows,
        "summary": {"cells": summary, "rules": len(rows), "rules_runnable_somewhere": runnable_somewhere},
    }


def navigator_layer(result: dict) -> dict:
    """An ATT&CK Navigator layer (v4.5): each technique scored by the share of SIEMs where its rule can run."""
    live = max(len(result["connections"]), 1)
    techniques = []
    for row in result["rows"]:
        ok = [c for c in row["cells"] if c["status"] == "runnable"]
        score = round(100 * len(ok) / live)
        comment = "; ".join(f"{c['connection']}: {c['status']}" + (f" ({c['reasons'][0]})" if c["reasons"] else "") for c in row["cells"])
        techniques.append({"techniqueID": row["technique"], "score": score, "comment": comment[:1000], "enabled": True})
    return {
        "name": "ORION hunt coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques ORION has a rule for, scored by the percentage of connected SIEMs on which the rule can actually run "
                       "(a field mapping exists and recent events carry the fields it needs).",
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#e06666", "#ffe599", "#6aa84f"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "No SIEM can run the rule", "color": "#e06666"},
                        {"label": "Runnable on some SIEMs", "color": "#ffe599"},
                        {"label": "Runnable on every connected SIEM", "color": "#6aa84f"}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }
