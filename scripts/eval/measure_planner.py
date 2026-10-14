"""Measure the AI planner: how many of its proposals survive validation, and whether the accepted rules produce results.

    python scripts/eval/measure_planner.py            # uses the configured AI provider
    python scripts/eval/measure_planner.py --stub     # dry run of this script with canned replies; writes nothing

For each of a fixed set of hunches it builds the same context a real investigation would give the planner
(what each live SIEM can see, the top findings), asks the real model, runs ORION's validation on the reply,
and for every accepted AI rule runs the translated query on the live SIEMs to see if it executes and returns events.
If the model cannot answer (quota, network) the output says "not measured": no numbers are invented.
Results: docs/evaluation/PLANNER.md and planner_results.json.
"""
import argparse
import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.core.database import async_session  # noqa: E402
from app.services.investigation.context import build_context  # noqa: E402
from app.services.investigation.proposer import propose_steps  # noqa: E402
from app.services.sigma_engine import convert_sigma_rule  # noqa: E402
from scripts.eval.run_evaluation import live_connectors, log  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "evaluation"

HYPOTHESES = [
    "An attacker left a netcat listener on the workstation to keep access.",
    "Someone is downloading tools onto the workstation with curl or wget.",
    "An attacker is hiding their tracks by clearing the shell history.",
    "A reverse shell was started through bash.",
    "A user is running unusual scripts from the /tmp directory.",
]


def _stub_call(prompt, system_prompt, name):
    ctx = json.loads(prompt.split("<untrusted_data>")[1].split("</untrusted_data>")[0])
    rule = ("title: stub\nlogsource: {product: linux, category: process_creation}\ndetection:\n  selection:\n"
            "    Image|endswith: '/nc'\n  condition: selection\ntags: [attack.discovery]\n")
    steps = [{"kind": "rule", "title": "stub rule", "rationale": "Image is populated.", "sigma_rule": rule, "cites": ["Image"]},
             {"kind": "rule", "title": "invented", "rationale": "x", "sigma_rule": rule, "cites": ["nothing-real"]}]
    text = json.dumps({"steps": steps})
    return text, {"context": name, "prompt": prompt, "system_prompt": system_prompt, "response": text,
                  "model": "stub", "provider": "stub", "latency_ms": 1}


async def measure_one(hypothesis: str, live: list, call) -> dict:
    inv = SimpleNamespace(id=uuid.uuid4(), title=hypothesis[:60], hypothesis=hypothesis,
                          siem_targets=[s["id"] for s in live], steps=[], source_finding_id=None)
    async with async_session() as db:
        context = await build_context(db, inv)
    targets = [{"conn_id": str(s["id"]), "name": s["name"], "siem_type": s["type"], "profile": s["profile"]} for s in live]
    proposal = await propose_steps(context, hypothesis, targets, set(), llm_call=call, guard_seconds=90)

    ai_answered = bool(proposal.audits) and proposal.audits[0].get("parsed") is not None
    ai_rules = [s for s in proposal.steps if s["proposed_by"] == "ai" and s["kind"] == "rule"]
    ai_pivots = [s for s in proposal.steps if s["proposed_by"] == "ai" and s["kind"] == "pivot"]
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")

    ran = []
    for step in ai_rules:
        conversion = convert_sigma_rule(step["payload"]["sigma_rule"])
        for siem in live:
            target = next((t for t in step["assessment"]["targets"] if t["connection"] == siem["name"]), None)
            if not target or not target["runnable"]:
                continue
            query = conversion.get({"elastic": "eql", "wazuh": "lucene"}[siem["type"]])
            try:
                events = await siem["connector"].run_query(query, max_results=1000, time_range={"from": since})
                ran.append({"siem": siem["type"], "ok": True, "events": len(events)})
            except Exception as e:
                ran.append({"siem": siem["type"], "ok": False, "error": type(e).__name__})
    rejected = proposal.rejected
    return {"hypothesis": hypothesis, "ai_answered": ai_answered, "notes": proposal.notes,
            "models": sorted({a.get("model", "?") for a in proposal.audits}),
            "accepted_rules": len(ai_rules), "accepted_pivots": len(ai_pivots), "rejected": len(rejected),
            "rejection_reasons": [r["reason"][:90] for r in rejected], "rule_runs": ran}


def render(results: list, meta: dict) -> str:
    answered = [r for r in results if r["ai_answered"]]
    lines = ["# ORION planner measurement", "",
             f"Run on {meta['date']}. Model(s) that answered: {meta['model']}.", ""]
    if not answered:
        lines += ["## Result: NOT MEASURED", "",
                  "The AI model did not answer any of the test hunches, so no planner quality number exists. "
                  "Reasons reported by the planner:", ""]
        lines += sorted({f"- {n}" for r in results for n in r["notes"]}) or ["- (none recorded)"]
        lines += ["", "Re-run `python scripts/eval/measure_planner.py` when the provider is available."]
        return "\n".join(lines) + "\n"

    proposed = sum(r["accepted_rules"] + r["accepted_pivots"] + r["rejected"] for r in answered)
    accepted = sum(r["accepted_rules"] + r["accepted_pivots"] for r in answered)
    runs = [x for r in answered for x in r["rule_runs"]]
    lines += ["## Result", "",
              f"- Hunches answered: {len(answered)} of {len(results)}",
              f"- Proposals made: {proposed}; accepted by validation: {accepted} "
              f"({100 * accepted / proposed:.0f}%)" if proposed else "- No proposals were made",
              f"- Accepted AI rules executed on a live SIEM without error: {sum(1 for x in runs if x['ok'])} of {len(runs)}",
              f"- ...and returned at least one event: {sum(1 for x in runs if x['ok'] and x['events'])} of {len(runs)}", "",
              "## Per hunch", "", "| Hunch | Accepted rules | Accepted pivots | Rejected | Rule runs (events) |", "|---|---|---|---|---|"]
    for r in results:
        runs_txt = ", ".join(f"{x['siem']}: {x['events'] if x['ok'] else x['error']}" for x in r["rule_runs"]) or "-"
        state = "" if r["ai_answered"] else " (AI did not answer)"
        lines.append(f"| {r['hypothesis']}{state} | {r['accepted_rules']} | {r['accepted_pivots']} | {r['rejected']} | {runs_txt} |")
    reasons = sorted({x for r in answered for x in r["rejection_reasons"]})
    if reasons:
        lines += ["", "## Why proposals were rejected", ""] + [f"- {x}" for x in reasons]
    lines += ["", "A returned event does not mean the rule is a good detection: it only means the rule is valid and runs. "
              "Whether it is useful needs the ground-truth markers of the main evaluation or an analyst's judgement.", "",
              "## Limits of this measurement", "",
              "- Five hunches, one run: a small sample, so the percentages are indicative only.",
              "- Model names such as `gemini-flash-latest` are moving aliases: the same name can mean a different model later, "
              "so a re-run may not reproduce these numbers. Pin a dated model name for the final thesis run.",
              "- Rejected proposals here were duplicates of the built-in suggestions; invalid-rule rejections are covered by unit tests only.",
              "- Some free-tier models are limited to a few requests per day, so a hunch can fall through every model in the chain.", ""]
    return "\n".join(lines)


async def main_async(stub: bool) -> None:
    live = await live_connectors()
    if not live:
        raise SystemExit("no live Elastic or Wazuh connection found")
    call = _stub_call if stub else None
    results = []
    for hypothesis in HYPOTHESES:
        log(f"asking the planner: {hypothesis}")
        results.append(await measure_one(hypothesis, live, call))
    if call is None:
        used = sorted({m for r in results for m in r["models"]})        # the models that REALLY answered
        model_name = ", ".join(used) if used else "none answered"
    else:
        model_name = "stub (dry run)"
    meta = {"date": datetime.now().strftime("%Y-%m-%d %H:%M"), "model": model_name}
    text = render(results, meta)
    if stub:
        print(text)
        return
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "PLANNER.md").write_text(text)
    (OUT_DIR / "planner_results.json").write_text(json.dumps({"meta": meta, "results": results}, indent=1))
    log(f"written: {OUT_DIR / 'PLANNER.md'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stub", action="store_true", help="dry run with canned replies; writes nothing")
    parser.add_argument("--render-only", action="store_true", help="rebuild PLANNER.md from planner_results.json (no model calls)")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    if args.render_only:
        saved = json.loads((OUT_DIR / "planner_results.json").read_text())
        (OUT_DIR / "PLANNER.md").write_text(render(saved["results"], saved["meta"]))
        log("PLANNER.md rebuilt from planner_results.json")
    else:
        asyncio.run(main_async(args.stub))
