"""Measure what ORION detects on real telemetry, per SIEM and combined.

    python scripts/eval/run_evaluation.py                 # all techniques except the file one
    python scripts/eval/run_evaluation.py --fim           # also the file-integrity technique
    python scripts/eval/run_evaluation.py --only T1046,T1105 --quick

What it does, for each technique in techniques.py:
  1. starts REAL harmless activity on this host: a long-lived instance, and several 1-second instances,
     each carrying a unique marker (the ground truth)
  2. polls each SIEM with the Sigma rule, converted by ORION's own pipeline (rule -> EQL / Lucene ->
     connector -> ECS), and records whether and when the marked event shows up
  3. counts the unrelated events the same rule returns (noise, the false-positive proxy)
  4. replays grouping, cross-SIEM correlation and priority scoring on what came back, and checks whether
     the marked behaviour ranks above the noise
Nothing is written to ORION's database. Results go to docs/evaluation/. Anything it cannot measure is
reported as "not measured", never guessed.
"""
import argparse
import asyncio
import json
import logging
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import yaml  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.database import async_session  # noqa: E402
from app.models import SIEMConnection  # noqa: E402
from app.services.connectors.factory import get_connector  # noqa: E402
from app.services.correlation import Candidate, correlate  # noqa: E402
from app.services.data_profile import blind_spots  # noqa: E402
from app.services.ecs import extract_ecs_fields, extract_mitre_from_tags, get_nested  # noqa: E402
from app.services.grouping import group_events  # noqa: E402
from app.services.prioritization import Signals, score  # noqa: E402
from app.services.sigma_engine import convert_sigma_rule, rule_fields, unmapped_fields  # noqa: E402
from scripts.eval import techniques as tech  # noqa: E402

POLL_SECONDS = 15
OUT_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "evaluation"


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


# ── setup ─────────────────────────────────────────────────────────────────────────

# [explain] Finds the SIEMs that received events recently. Archives (like the old demo index) are left out.
async def live_connectors() -> list:
    """Active connections that have received events recently (archives are left out)."""
    live = []
    async with async_session() as db:
        for conn in (await db.execute(select(SIEMConnection).where(SIEMConnection.is_active.is_(True)))).scalars().all():
            if conn.type not in ("elastic", "wazuh"):
                continue
            connector = get_connector(conn)
            try:
                profile = await connector.profile(1)
            except Exception as e:
                log(f"skipping {conn.name}: {type(e).__name__}")
                continue
            if profile.get("recent_docs"):
                live.append({"name": conn.name, "type": conn.type, "connector": connector, "profile": profile})
    return live


# [explain] For each live SIEM: the translated query, or the reason the rule cannot run there.
def compile_queries(technique, live: list) -> dict:
    """Per live SIEM: the native query, or why the rule cannot run there."""
    conversion = convert_sigma_rule(technique.rule)
    used = rule_fields(technique.rule)
    out = {}
    for siem in live:
        key = {"elastic": "eql", "wazuh": "lucene"}[siem["type"]]
        reasons = []
        if not conversion.get(key):
            reasons.append("no query could be generated")
        missing = unmapped_fields(technique.rule, siem["type"])
        if missing:
            reasons.append("no field mapping for " + ", ".join(missing))
        reasons += [f"blind spot: {b}" for b in blind_spots(used, siem["type"], siem["profile"])]
        out[siem["name"]] = {"query": conversion.get(key), "runnable": not reasons, "reasons": reasons}
    return out


# [explain] Run the query on one SIEM for events since the start of the experiment.
async def fetch(siem: dict, query: str, since: str) -> list:
    try:
        return await siem["connector"].run_query(query, max_results=1000, time_range={"from": since})
    except Exception as e:
        log(f"query failed on {siem['name']}: {type(e).__name__}: {str(e)[:120]}")
        return []


def blob(event: dict) -> str:
    return json.dumps(event, default=str)


# ── the experiment ────────────────────────────────────────────────────────────────

# [explain] The experiment itself: start the activities on a schedule, poll every 15 s, note when each marked event first appears,
# [explain] stop everything, and do one last check.
async def run(args) -> dict:
    live = await live_connectors()
    if not live:
        raise SystemExit("no live Elastic or Wazuh connection found (is the lab running?)")
    log("live sources: " + ", ".join(f"{s['name']} [{s['type']}]" for s in live))

    run_id = datetime.now().strftime("%H%M%S")
    chosen = [t for t in tech.TECHNIQUES
              if (not args.only or t.key in args.only) and (args.fim or not t.needs_fim)]
    queries = {t.key: compile_queries(t, live) for t in chosen}
    for t in chosen:
        for name, q in queries[t.key].items():
            log(f"{t.key} on {name}: " + ("runnable" if q["runnable"] else "NOT runnable: " + "; ".join(q["reasons"])))

    helper, helper_port = tech.start_helper_listener()
    time.sleep(0.5)
    started = time.time()
    since = datetime.fromtimestamp(started - 30, timezone.utc).isoformat().replace("+00:00", "Z")
    instances = {t.key: [] for t in chosen}
    first_seen = {}                       # (technique, siem name, marker) -> seconds after start
    last_events = {}                      # (technique, siem name) -> events from the latest poll

    # schedule: long variants at once, short ones spread over the first minute, file changes after 10 s
    schedule = []
    for index, t in enumerate(chosen):
        for variant in t.variants:
            if variant == "long" or variant == "file":
                schedule.append((10 if variant == "file" else 0, t, variant))
            else:
                # techniques are staggered so one lucky sample cannot catch several of them at once
                schedule += [(5 + i * args.short_gap + index * 0.7, t, variant) for i in range(args.short_repeats)]
    schedule.sort(key=lambda x: x[0])
    holds = [t.hold for t in chosen if "long" in t.variants or "file" in t.variants]
    deadline = started + (args.max_wait or (max(holds) if holds else 60) + 30)
    if args.quick:
        deadline = started + 150

    try:
        next_poll = started
        while time.time() < deadline:
            now = time.time() - started
            while schedule and schedule[0][0] <= now:
                _, t, variant = schedule.pop(0)
                inst = t.launch(run_id, variant, helper_port)
                inst.started_at = time.time()
                instances[t.key].append(inst)
                if variant != "short":
                    log(f"started {t.key} ({variant}) marker={inst.marker}")
            for insts in instances.values():
                for inst in insts:
                    if inst.kill_after is not None and not inst.stopped and time.time() - inst.started_at >= inst.kill_after:
                        tech.stop(inst)
            if time.time() >= next_poll:
                next_poll = time.time() + POLL_SECONDS
                for t in chosen:
                    for siem in live:
                        q = queries[t.key][siem["name"]]
                        if not q["runnable"]:
                            continue
                        events = await fetch(siem, q["query"], since)
                        last_events[(t.key, siem["name"])] = events
                        text = [blob(e) for e in events]
                        for inst in instances[t.key]:
                            k = (t.key, siem["name"], inst.marker)
                            if k not in first_seen and any(inst.matches(x) for x in text):
                                first_seen[k] = time.time() - inst.started_at
                                log(f"SEEN {t.key} {inst.variant} on {siem['name']} after {first_seen[k]:.0f}s")
                pending = [(t, s) for t in chosen for s in live if queries[t.key][s["name"]]["runnable"]
                           and any(i.variant in ("long", "file") and (t.key, s["name"], i.marker) not in first_seen
                                   for i in instances[t.key])]
                if not schedule and not pending:
                    log("every runnable pair was detected: stopping early")
                    break
            await asyncio.sleep(1)
    finally:
        for insts in instances.values():
            for inst in insts:
                tech.stop(inst)
        helper.terminate()

    log("final ingestion pass")
    await asyncio.sleep(20)
    for t in chosen:
        for siem in live:
            q = queries[t.key][siem["name"]]
            if q["runnable"]:
                last_events[(t.key, siem["name"])] = await fetch(siem, q["query"], since)
                text = [blob(e) for e in last_events[(t.key, siem["name"])]]
                for inst in instances[t.key]:
                    k = (t.key, siem["name"], inst.marker)
                    if k not in first_seen and any(inst.matches(x) for x in text):
                        first_seen[k] = time.time() - inst.started_at

    return {"run_id": run_id, "live": live, "chosen": chosen, "queries": queries, "instances": instances,
            "first_seen": first_seen, "events": last_events, "started": started}


# ── analysis ──────────────────────────────────────────────────────────────────────

# [explain] Turns what was observed into numbers: detected/run, time to appear, noise, behaviours after grouping.
def analyse(raw: dict) -> dict:
    out = {"techniques": [], "sources": [{"name": s["name"], "type": s["type"],
                                         "recent_events": s["profile"]["recent_docs"]} for s in raw["live"]]}
    for t in raw["chosen"]:
        rec = {"key": t.key, "name": t.name, "tactic": t.tactic, "per_siem": {}}
        tags = (yaml.safe_load(t.rule) or {}).get("tags", [])
        tactics = extract_mitre_from_tags(tags)[0]
        scoped = []                         # (siem type, siem name, group) for the ranking replay
        for siem in raw["live"]:
            name = siem["name"]
            q = raw["queries"][t.key][name]
            res = {"type": siem["type"], "runnable": q["runnable"], "reasons": q["reasons"], "variants": {}}
            if q["runnable"]:
                events = raw["events"].get((t.key, name), [])
                texts = [blob(e) for e in events]
                insts = raw["instances"][t.key]
                for variant in t.variants:
                    mine = [i for i in insts if i.variant == variant]
                    seen = [raw["first_seen"][(t.key, name, i.marker)] for i in mine if (t.key, name, i.marker) in raw["first_seen"]]
                    res["variants"][variant] = {
                        "instances": len(mine), "detected": len(seen),
                        "latency_s_median": round(statistics.median(seen)) if seen else None,
                    }
                noise = [e for e, x in zip(events, texts) if not any(i.matches(x) for i in insts)]
                items = [(e, extract_ecs_fields(e)) for e in events]
                groups = group_events(siem["type"], items)
                noise_groups = [g for g in groups if not any(i.matches(blob(g.event)) for i in insts)]
                res.update({"raw_events": len(events), "noise_events": len(noise), "behaviours": len(groups),
                            "noise_behaviours": len(noise_groups)})
                scoped += [(siem["type"], name, g) for g in groups]
            rec["per_siem"][name] = res
        rec["ranking"] = ranking_replay(t, tactics, scoped, raw["instances"][t.key])
        out["techniques"].append(rec)
    return out


# [explain] Replays grouping, correlation and scoring on the events and asks: does the real scenario come first,
# [explain] when sorted by newest and when sorted by priority?
def ranking_replay(t, tactics, scoped, insts) -> dict:
    """Does the marked behaviour rank above the noise? Real grouping, correlation and scoring, offline."""
    if not scoped:
        return {"measured": False}
    candidates = [Candidate(stype, g.fields.get("host_name"), g.fields.get("process_name"), g.first_seen, g.last_seen)
                  for stype, _, g in scoped]
    ids = correlate(candidates)
    rows = []
    for (stype, _, g), corr in zip(scoped, ids):
        others = tuple(sorted({s2 for (s2, _, _), c2 in zip(scoped, ids) if corr and c2 == corr and s2 != stype}))
        span = max(0.0, (g.last_seen - g.first_seen).total_seconds() / 60)
        result = score(Signals(
            siem_type=stype, other_sources=others, tactics=tuple(tactics),
            event_level=get_nested(g.event, "event.severity"), occurrence_count=g.count, span_minutes=span,
            derived=bool(get_nested(g.event, "orion.derived_from")), has_process=bool(g.fields.get("process_name")),
        ))
        is_tp = any(i.matches(blob(g.event)) for i in insts)
        rows.append({"tp": is_tp, "score": result.score, "last": g.last_seen})
    if not any(r["tp"] for r in rows):
        return {"measured": True, "behaviours": len(rows), "true_positives": 0}

    def precision_at(order, k):
        top = order[:k]
        return round(sum(r["tp"] for r in top) / len(top), 2)

    by_score = sorted(rows, key=lambda r: (r["score"], r["last"]), reverse=True)
    by_time = sorted(rows, key=lambda r: r["last"], reverse=True)
    return {"measured": True, "behaviours": len(rows), "true_positives": sum(r["tp"] for r in rows),
            "p_at_1": {"by_time": precision_at(by_time, 1), "by_priority": precision_at(by_score, 1)},
            "p_at_3": {"by_time": precision_at(by_time, 3), "by_priority": precision_at(by_score, 3)}}


# ── report ────────────────────────────────────────────────────────────────────────

def cell(variant_res) -> str:
    if variant_res is None:
        return "-"
    n, d = variant_res["instances"], variant_res["detected"]
    text = f"{d}/{n}"
    if variant_res.get("latency_s_median") is not None:
        text += f" ({variant_res['latency_s_median']} s)"
    return text


# [explain] Writes the summary sentences straight from the numbers, so text and tables can never disagree.
def summary_lines(analysis: dict) -> list:
    """What the numbers say, computed from them (so it can never drift from the tables below)."""
    by_siem = {}
    for t in analysis["techniques"]:
        for name, res in t["per_siem"].items():
            if not res["runnable"]:
                continue
            agg = by_siem.setdefault(name, {"type": res["type"], "long": [0, 0], "short": [0, 0], "lat": [], "noise": 0, "raw": 0})
            for variant, vr in res["variants"].items():
                key = "short" if variant == "short" else "long"
                agg[key][0] += vr["detected"]
                agg[key][1] += vr["instances"]
                if key == "long" and vr.get("latency_s_median") is not None:
                    agg["lat"].append(vr["latency_s_median"])
            agg["noise"] += res["noise_events"]
            agg["raw"] += res["raw_events"]
    out = []
    for name, a in by_siem.items():
        lat = f", median time to appear {statistics.median(a['lat']):.0f} s" if a["lat"] else ""
        short = f"{a['short'][0]}/{a['short'][1]} one-second instances" if a["short"][1] else "no short instances"
        out.append(f"- **{name}** ({a['type']}): caught {a['long'][0]}/{a['long'][1]} long-lived scenarios{lat}; "
                   f"caught {short}; {a['noise']} of {a['raw']} returned events were unrelated to the scenarios.")
    both = sum(1 for t in analysis["techniques"] for v in ("long",)
               if all(r["runnable"] and r["variants"].get(v, {}).get("detected") for r in t["per_siem"].values()))
    total = len(analysis["techniques"])
    out.append(f"- Techniques whose long-lived instance was seen by **every** live SIEM: {both} of {total}. "
               f"Where only one SIEM sees an activity, the other's silence is a coverage gap, not a clean result.")
    return out


# [explain] Writes docs/evaluation/RESULTS.md (for reading) and results.json (the raw numbers).
def write_report(analysis: dict, meta: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "results.json").write_text(json.dumps({"meta": meta, **analysis}, indent=1, default=str))

    sources = analysis["sources"]
    lines = [
        "# ORION evaluation results", "",
        f"Run on {meta['date']} against real telemetry from one Linux host (WSL2). Commit `{meta['commit']}`. "
        f"Each technique was executed as harmless local activity with a unique marker; a detection counts only if the "
        f"returned event carries that marker. Unrelated matches are reported as noise (the false-positive proxy).", "",
        "## Sources", "",
    ]
    for s in sources:
        lines.append(f"- {s['name']} ({s['type']}): {s['recent_events']:,} events in the last day")
    lines += ["", "## Summary", ""] + summary_lines(analysis)
    lines += ["", "## 1. Detection per technique and per SIEM", "",
              "Cells are `detected / run` with the median time to first appearance. *long* = alive for the whole window, "
              "*short* = alive about one second.", ""]
    head = ["Technique", "Variant"] + [f"{s['type']}" + (f" ({i + 1})" if sum(1 for x in sources if x['type'] == s['type']) > 1 else "")
                                          for i, s in enumerate(sources)] + ["Either"]
    lines += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for t in analysis["techniques"]:
        variants = []
        for res in t["per_siem"].values():
            for v in res["variants"]:
                if v not in variants:
                    variants.append(v)
        variants = variants or ["long"]
        for v in variants:
            row, either = [f"{t['key']} {t['name']}", v], False
            for name, res in t["per_siem"].items():
                if not res["runnable"]:
                    row.append("not runnable: " + "; ".join(res["reasons"]))
                else:
                    vr = res["variants"].get(v)
                    row.append(cell(vr))
                    either = either or bool(vr and vr["detected"])
            row.append("yes" if either else "no")
            lines.append("| " + " | ".join(row) + " |")

    lines += ["", "## 2. Noise: what the same rule returns that is NOT the scenario", "",
              "| Technique | SIEM | Raw events | Unrelated events | Behaviours after grouping | Unrelated behaviours |",
              "|---|---|---|---|---|---|"]
    for t in analysis["techniques"]:
        for name, res in t["per_siem"].items():
            if res["runnable"]:
                lines.append(f"| {t['key']} | {res['type']} | {res['raw_events']} | {res['noise_events']} | "
                             f"{res['behaviours']} | {res['noise_behaviours']} |")

    lines += ["", "## 3. Does priority scoring put the scenario first?", "",
              "Precision at k of the list ordered by newest-first versus by ORION's priority score "
              "(grouping, correlation and scoring replayed offline on the events above; no analyst labels).", "",
              "| Technique | Behaviours | True positives | P@1 newest | P@1 priority | P@3 newest | P@3 priority |",
              "|---|---|---|---|---|---|---|"]
    gains = []
    for t in analysis["techniques"]:
        r = t["ranking"]
        if r.get("p_at_1"):
            lines.append(f"| {t['key']} | {r['behaviours']} | {r['true_positives']} | {r['p_at_1']['by_time']} | "
                         f"{r['p_at_1']['by_priority']} | {r['p_at_3']['by_time']} | {r['p_at_3']['by_priority']} |")
            gains.append((r["p_at_1"]["by_priority"] - r["p_at_1"]["by_time"], r["p_at_3"]["by_priority"] - r["p_at_3"]["by_time"]))
        else:
            lines.append(f"| {t['key']} | {r.get('behaviours', 0)} | {r.get('true_positives', 0)} | n/a | n/a | n/a | n/a |")
    if gains:
        lines.append("")
        lines.append(f"Mean change in P@1 from priority ordering: {statistics.mean(g[0] for g in gains):+.2f}; "
                     f"in P@3: {statistics.mean(g[1] for g in gains):+.2f}.")

    not_measured = [
        "- **AI planner quality** (how many proposed rules validate and produce hits): the model quota was exhausted "
        "and no real model reply has been observed. The validation logic is unit-tested with stubbed replies only.",
        "- **Analyst time saved** (the 30-90 minute manual-hunt claim): needs a timed study with human analysts; none was run.",
        "- **Effect of analyst feedback over time** (suppression, history in scoring): no labelled analyst decisions exist yet, "
        "and the scoring weights have not been calibrated.",
    ]
    if not any(t["key"] == "T1565.001" for t in analysis["techniques"]):
        not_measured.append(
            "- **File-integrity technique (T1565.001)**: not run in this report. It needs "
            "`sudo bash scripts/lab/enable_fim_demo.sh` and `--fim`, and is where Wazuh is expected to see what process telemetry cannot.")
    not_measured.append("- **Windows telemetry, network telemetry, other SIEMs**: the lab has one Linux host, Elastic and Wazuh only.")

    validity = [
        "- One host, one run: latencies depend on Metricbeat's 30 s period and Wazuh's 360 s listening-port check.",
        "- The techniques are simulated with harmless commands; real adversary tooling may behave differently.",
        "- The Sigma rules are deliberately broad; a tighter rule would lower noise and could change what is detected.",
        "- Short-lived processes are caught by sampling with a probability of roughly duration / period; with few repeats the "
        "catch rate is a rough estimate, not a precise figure.",
    ]
    lines += ["", "## 4. Not measured", ""] + not_measured + ["", "## 5. Threats to validity", ""] + validity + [""]
    (OUT_DIR / "RESULTS.md").write_text("\n".join(lines))


# [explain] Command line: choose techniques, include file changes, quick mode, or rebuild the report from saved results.
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", type=lambda v: v.split(","), default=None, help="comma-separated technique keys")
    parser.add_argument("--fim", action="store_true", help="include the file-integrity technique (needs scripts/lab/enable_fim_demo.sh)")
    parser.add_argument("--quick", action="store_true", help="stop after 150 s (the Wazuh listening-port check will not be reached)")
    parser.add_argument("--short-repeats", type=int, default=30)
    parser.add_argument("--short-gap", type=int, default=3, help="seconds between short-lived instances")
    parser.add_argument("--max-wait", type=int, default=None)
    parser.add_argument("--from-json", action="store_true", help="rebuild RESULTS.md from the saved results.json (no experiment)")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)

    if args.from_json:
        saved = json.loads((OUT_DIR / "results.json").read_text())
        meta = saved.pop("meta")
        write_report(saved, meta)
        log(f"report rebuilt from results.json: {OUT_DIR / 'RESULTS.md'}")
        return

    raw = asyncio.run(run(args))
    analysis = analyse(raw)
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    meta = {"date": datetime.now().strftime("%Y-%m-%d %H:%M"), "commit": commit or "unknown",
            "platform": platform.platform(), "python": platform.python_version(), "run_id": raw["run_id"]}
    write_report(analysis, meta)
    log(f"written: {OUT_DIR / 'RESULTS.md'}")


if __name__ == "__main__":
    main()
