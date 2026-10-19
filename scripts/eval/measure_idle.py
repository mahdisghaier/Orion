"""False positives and event reduction on real background activity.

The monitored host runs no scenario during the window: what the SIEMs hold is what the machine does by itself (system
services, package checks, the sensors themselves, SSH sessions). Every rule of the library runs on both SIEMs over the
window. Whatever a rule returns is a false positive, since nothing of the window is an attack. The events of the window
are also grouped to measure how much the grouping reduces a stream of real, unscripted events.

    python scripts/eval/measure_idle.py --from 2026-10-19T12:30:00Z --to 2026-10-19T14:30:00Z --host orion-lab
"""
import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "eval"))

from run_evaluation import live_connectors  # noqa: E402
from app.services.data_profile import blind_spots  # noqa: E402
from app.services.ecs import extract_ecs_fields, get_nested  # noqa: E402
from app.services.grouping import group_events  # noqa: E402
from app.services.sigma_engine import convert_sigma_rule, rule_fields, unmapped_fields  # noqa: E402
from app.services.threat_intel.rules import library  # noqa: E402

ALL_PROCESS_EQL = 'process where host.name == "{host}" and event.action == "executed"'
ALL_PROCESS_LUCENE = "rule.id:100200"


def when(event: dict) -> datetime:
    return extract_ecs_fields(event)["event_time"]


async def window_events(siem: dict, query: str, start: str, end: str, host: str) -> list:
    """Every matching event of the window, fetched in slices of the stored limit (1,000 events per query)."""
    out, cursor = [], datetime.fromisoformat(start.replace("Z", "+00:00"))
    stop = datetime.fromisoformat(end.replace("Z", "+00:00"))
    step = (stop - cursor) / 48
    while cursor < stop:
        nxt = min(cursor + step, stop)
        events = await siem["connector"].run_query(
            query, max_results=1000, time_range={"from": cursor.isoformat().replace("+00:00", "Z"), "to": nxt.isoformat().replace("+00:00", "Z")})
        out += [e for e in events if str(get_nested(e, "host.name") or "").lower() == host.lower()]
        cursor = nxt
    return out


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from", dest="start", required=True)
    parser.add_argument("--to", dest="end", required=True)
    parser.add_argument("--host", default="orion-lab")
    parser.add_argument("--connections", type=lambda v: v.split(","), default=["Auditbeat", "Wazuh"])
    parser.add_argument("--out", default="idle")
    args = parser.parse_args()

    sources = await live_connectors(args.connections)
    report = {"window": [args.start, args.end], "host": args.host, "siems": {}}
    for siem in sources:
        key = {"elastic": "eql", "wazuh": "lucene"}[siem["type"]]
        base = (ALL_PROCESS_EQL.format(host=args.host) if siem["type"] == "elastic" else ALL_PROCESS_LUCENE)
        events = await window_events(siem, base, args.start, args.end, args.host)
        items = [(e, extract_ecs_fields(e)) for e in events]
        behaviours = group_events(siem["type"], items)
        rules = []
        for rule in library():
            y = rule["yaml"]
            if unmapped_fields(y, siem["type"]) or blind_spots(rule_fields(y), siem["type"], siem["profile"]):
                rules.append({"technique": rule["technique"], "title": rule["title"], "status": "not runnable"})
                continue
            hits = await window_events(siem, convert_sigma_rule(y)[key], args.start, args.end, args.host)
            grouped = group_events(siem["type"], [(e, extract_ecs_fields(e)) for e in hits])
            rules.append({"technique": rule["technique"], "title": rule["title"], "status": "ran", "events": len(hits),
                          "behaviours": len(grouped),
                          "examples": sorted({(extract_ecs_fields(g.event)["process_command_line"] or "")[:90] for g in grouped})[:3]})
        report["siems"][siem["name"]] = {"type": siem["type"], "process_events": len(events), "behaviours": len(behaviours), "rules": rules}

    out = ROOT / "docs" / "evaluation" / args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(report, indent=1))
    lines = ["# False positives and reduction on background activity", "",
             f"Window {args.start} to {args.end} on {args.host}, no scenario running. Whatever a rule returns here is a false positive.", ""]
    for name, r in report["siems"].items():
        lines += [f"## {name}", "",
                  f"Process starts in the window: {r['process_events']}, grouped into {r['behaviours']} behaviours.", "",
                  "| Technique | Rule | Events | Behaviours | Examples |", "|---|---|---|---|---|"]
        for x in r["rules"]:
            if x["status"] == "ran":
                lines.append(f"| {x['technique']} | {x['title']} | {x['events']} | {x['behaviours']} | {'; '.join(x['examples'])} |")
            else:
                lines.append(f"| {x['technique']} | {x['title']} | not runnable | | |")
        lines.append("")
    (out / "RESULTS.md").write_text("\n".join(lines))
    print("written", out)


if __name__ == "__main__":
    asyncio.run(main())
