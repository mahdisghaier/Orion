"""Export an investigation: a PDF report for people and a Jupyter notebook that replays it.

Both are built ONLY from the stored hunt record (hypothesis, steps, who approved what, results, data
coverage, model usage), so they say what actually happened. Neither contains a credential:
  - the notebook re-runs steps through ORION's own API (SIEM secrets stay on the server) and reads the
    analyst's ORION login from the environment (ORION_EMAIL / ORION_PASSWORD) at run time
  - the report lists data sources by name and type only

An open investigation exports as a DRAFT.
"""
import html
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HuntResult, Investigation, LLMAudit, SIEMConnection, SIEMProfile, User
from app.services.corroboration import enrich_findings
from app.services.ecs import extract_mitre_from_tags

# [explain] The report lists at most 15 behaviours, most important first, so it stays readable.
MAX_REPORT_FINDINGS = 15


# [explain] Everything a report or notebook needs, gathered once from the saved record (never from memory or the AI).
@dataclass
class ExportData:
    inv: Investigation
    people: Dict[object, str] = field(default_factory=dict)          # user id -> "Name (role)"
    connections: List[dict] = field(default_factory=list)            # name, type, profile, collected_at
    findings: List[HuntResult] = field(default_factory=list)         # best finding per behaviour, by priority
    ai: dict = field(default_factory=dict)                           # model usage for this investigation
    techniques: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# [explain] Reads who did what, which SIEMs and their check-ups, the best finding of each behaviour, and how much the AI was used.
async def gather_export_data(db: AsyncSession, inv: Investigation) -> ExportData:
    data = ExportData(inv=inv)

    user_ids = {inv.created_by, inv.concluded_by, *[s.decided_by for s in inv.steps]} - {None}
    if user_ids:
        for u in (await db.execute(select(User).where(User.id.in_(user_ids)))).scalars().all():
            data.people[u.id] = f"{u.full_name} ({u.role})"

    connections = (await db.execute(
        select(SIEMConnection).where(SIEMConnection.id.in_(inv.siem_targets))
    )).scalars().all()
    profiles = {
        r.siem_connection_id: r
        for r in (await db.execute(
            select(SIEMProfile).where(SIEMProfile.siem_connection_id.in_([c.id for c in connections]))
        )).scalars().all()
    }
    for c in connections:
        row = profiles.get(c.id)
        data.connections.append({"name": c.name, "type": c.type, "active": c.is_active,
                                 "profile": row.profile if row else None,
                                 "collected_at": row.collected_at if row else None})

    hunt_ids = [s.hunt_id for s in inv.steps if s.hunt_id]
    if hunt_ids:
        rows = (await db.execute(
            select(HuntResult).where(HuntResult.hunt_id.in_(hunt_ids))
            .order_by(HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc()).limit(200)
        )).scalars().all()
        seen, unique = set(), []
        for f in rows:
            key = f.fingerprint or str(f.id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        data.findings = await enrich_findings(db, unique[:MAX_REPORT_FINDINGS])

    audits = (await db.execute(
        select(LLMAudit.provider, LLMAudit.model, LLMAudit.was_rejected).where(LLMAudit.chat_session_id == inv.id)
    )).all()
    data.ai = {
        "calls": len(audits),
        "models": sorted({f"{p}/{m}" for p, m, _ in audits}),
        "unusable_replies": sum(1 for _, _, rej in audits if rej),
        "steps_proposed_by_ai": sum(1 for s in inv.steps if s.proposed_by == "ai"),
        "steps_proposed_by_rules": sum(1 for s in inv.steps if s.proposed_by == "system"),
        "steps_added_by_analyst": sum(1 for s in inv.steps if s.proposed_by == "analyst"),
    }

    techniques = set()
    for f in data.findings:
        techniques.update(f.mitre_techniques or [])
    for s in inv.steps:
        if s.kind == "rule":
            try:
                tags = (yaml.safe_load(s.payload.get("sigma_rule", "")) or {}).get("tags", [])
                techniques.update(extract_mitre_from_tags(tags)[1])
            except Exception:
                pass
    data.techniques = sorted(techniques)
    return data


# ── helpers ──────────────────────────────────────────────────────────────────────

def _when(ts) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "-"


def _who(data: ExportData, user_id) -> str:
    return data.people.get(user_id, "unknown") if user_id else "-"


def _proposer(p: str) -> str:
    return {"ai": "proposed by the AI planner", "system": "rule-based suggestion",
            "analyst": "added by an analyst"}.get(p, p)


def _outcome(step) -> str:
    r = step.result or {}
    if step.status == "rejected":
        return "Rejected by the analyst; not run."
    if step.status == "failed":
        return f"Failed: {step.error}"
    if step.status == "proposed":
        return "Never decided; not run."
    if step.kind == "rule":
        text = f"Hunt {r.get('hunt_status')}: {r.get('total_hits', 0)} finding(s)."
        return text + (f" Notes: {r['notes']}" if r.get("notes") else "")
    return f"{r.get('count', 0)} related event(s) from {r.get('connection_name', '?')}, +/-{r.get('window_minutes', '?')} min."


# [explain] The details a SIEM had NO recent data for: these go in the report as "could not see".
def blind_fields(profile: Optional[dict]) -> List[str]:
    if not profile or not profile.get("recent_docs"):
        return []
    return sorted(f for f, v in profile.get("fields", {}).items() if v["present"] == 0)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "investigation"


# ── notebook ─────────────────────────────────────────────────────────────────────

def _lines(text: str) -> List[str]:
    return text.splitlines(keepends=True) or [""]


def _md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": _lines(text)}


def _code(text: str, tags: Optional[List[str]] = None) -> dict:
    meta = {"tags": tags} if tags else {}
    return {"cell_type": "code", "metadata": meta, "execution_count": None, "outputs": [], "source": _lines(text)}


# [explain] Writes any text (like a Sigma rule) as a safe Python string for the notebook, keeping YAML readable when possible.
def _py_literal(text: str) -> str:
    """A Python literal for arbitrary text that keeps YAML readable when it can."""
    if "'''" not in text and not text.endswith("\\") and "\r" not in text:
        return "r'''" + text.strip("\n") + "\n'''"
    return repr(text)


_HELPERS = '''import os, json, httpx

client = httpx.Client(base_url=ORION_URL, timeout=120)
login = client.post("/api/auth/login", json={"email": os.environ["ORION_EMAIL"], "password": os.environ["ORION_PASSWORD"]})
login.raise_for_status()


def orion(method, path, **kwargs):
    """Call ORION's API. The SIEMs are only ever queried by ORION, read-only."""
    response = client.request(method, path, **kwargs)
    if response.status_code >= 400:
        detail = response.json().get("detail", response.text) if response.headers.get("content-type", "").startswith("application/json") else response.text
        raise RuntimeError(f"{response.status_code}: {detail}")
    return response.json()


def show(rows, columns, limit=20):
    """Print a small table."""
    print(" | ".join(columns))
    for row in rows[:limit]:
        print(" | ".join(str(row.get(c, "")) if not isinstance(row.get(c), (dict, list)) else "..." for c in columns))
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more")
'''


# [explain] Writes the Jupyter notebook: a title, a parameters cell, a helper that logs in from environment variables,
# [explain] and one cell per APPROVED step to replay it. Rejected or undecided steps are only described.
def build_notebook(data: ExportData) -> dict:
    inv = data.inv
    cells: List[dict] = []
    state = "DRAFT (still open)" if inv.status == "open" else f"CONCLUDED: {(inv.verdict or '').replace('_', ' ')}"

    cells.append(_md(
        f"# {inv.title}\n\n"
        f"**Status:** {state}  \n"
        f"**Hypothesis:** {inv.hypothesis}\n\n"
        f"Opened {_when(inv.created_at)} by {_who(data, inv.created_by)}. Generated by ORION on {_when(data.generated_at)}.\n\n"
        "This notebook replays the investigation step by step through ORION's API. It never contains a credential: "
        "export `ORION_EMAIL` and `ORION_PASSWORD` before running (an ORION analyst account). The SIEMs are queried by "
        "ORION, read-only. Needs `httpx` in the kernel's environment. Re-running a hunt step creates a new hunt in ORION, "
        "so results can differ from the original: that is the point of replaying it on current data."))

    targets = [str(t) for t in inv.siem_targets]
    cells.append(_code(
        "# Parameters: override these (for example with papermill); never put credentials here.\n"
        'ORION_URL = "http://localhost:8000"\n'
        f"SIEM_TARGETS = {json.dumps(targets)}   # the connections this investigation used\n"
        "TIME_RANGE = None                  # e.g. {\"from\": \"now-7d\"} to replay on recent data only\n",
        tags=["parameters"]))
    cells.append(_code(_HELPERS))

    for step in inv.steps:
        decided = ""
        if step.decided_at:
            decided = (f"{'Approved' if step.status in ('approved', 'executed', 'failed') else 'Rejected'} by "
                       f"{_who(data, step.decided_by)} on {_when(step.decided_at)}"
                       + (f': "{step.decision_comment}"' if step.decision_comment else ""))
        cells.append(_md(
            f"### Step {step.seq}: {step.title}\n\n"
            f"*{'Hunt a Sigma rule' if step.kind == 'rule' else 'Pivot on a finding'}, {_proposer(step.proposed_by)}.*\n\n"
            f"**Why:** {step.rationale}\n\n"
            + (f"**Decision:** {decided}\n\n" if decided else "")
            + f"**Original outcome:** {_outcome(step)}"))

        if step.status not in ("executed", "failed"):
            continue                                   # rejected / never decided steps are never replayed
        if step.kind == "rule":
            cells.append(_code(
                f"RULE_{step.seq} = {_py_literal(step.payload['sigma_rule'])}\n\n"
                f'hunt = orion("POST", "/api/hunts/", json={{"rule_yaml": RULE_{step.seq}, "siem_targets": SIEM_TARGETS, "time_range": TIME_RANGE}})\n'
                'print(hunt["status"], "-", hunt["total_hits"], "finding(s)", hunt["error"] or "")\n'
                'results = orion("GET", f"/api/hunts/{hunt[\'id\']}/results")\n'
                'show(results, ["siem_type", "host_name", "process_name", "process_command_line", "priority_score", "occurrence_count"])\n'))
        else:
            p = step.payload
            cells.append(_code(
                f'FINDING_{step.seq} = "{p["finding_id"]}"   # the finding this pivot ran on; use a finding of a fresh hunt to replay on current data\n\n'
                f'ctx = orion("GET", f"/api/findings/{{FINDING_{step.seq}}}/context", params={{"pivot": "{p["pivot"]}", "window": {int(p["window_minutes"])}}})\n'
                'print(ctx["count"], "event(s) from", ctx["connection_name"])\n'
                'show(ctx["events"], ["time", "host", "process_name", "command_line", "action"])\n'))

    cells.append(_md(
        "## Conclusion\n\n"
        + (f"**Verdict:** {(inv.verdict or '').replace('_', ' ')}  \n{inv.conclusion}\n\n"
           f"Closed {_when(inv.concluded_at)} by {_who(data, inv.concluded_by)}."
           if inv.status == "concluded" else "The investigation is still open: no conclusion has been recorded.")))

    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
            "orion": {"investigation_id": str(inv.id), "generated_at": data.generated_at.isoformat()},
        },
        "nbformat": 4,
        "nbformat_minor": 4,
    }


# ── PDF report ───────────────────────────────────────────────────────────────────

def _pdf_text(value) -> str:
    """Escape for ReportLab paragraphs; the built-in fonts only cover Latin-1."""
    text = html.escape(str(value if value is not None else ""), quote=False)
    return text.encode("latin-1", "replace").decode("latin-1")


# [explain] Draws the PDF: hypothesis and conclusion, what the SIEMs could and could not see, the timeline with who approved what,
# [explain] the evidence, the roles of AI and analyst, and the limitations. An open investigation is stamped DRAFT.
def build_report_pdf(data: ExportData, compress: bool = True) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    inv = data.inv
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontSize=9.5, leading=13, alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#444444"))
    h1 = ParagraphStyle("h1", parent=base["Heading1"], fontSize=18, leading=22, textColor=colors.HexColor("#142840"))
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, leading=16, spaceBefore=14,
                        textColor=colors.HexColor("#1a4a7a"))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)

    def P(text, style=body):
        return Paragraph(_pdf_text(text), style)

    def grid(rows, widths, header=True):
        table = Table([[Paragraph(_pdf_text(c), cell) for c in row] for row in rows], colWidths=widths, repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d0d8")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef5")))
        table.setStyle(TableStyle(style))
        return table

    draft = inv.status == "open"
    verdict = (inv.verdict or "none").replace("_", " ")
    story: list = [
        P("ORION  |  Investigation report", small),
        P(inv.title, h1),
        P(("DRAFT: this investigation is still open." if draft else f"Verdict: {verdict}"), body),
        Spacer(1, 4),
        grid([["Opened", f"{_when(inv.created_at)} by {_who(data, inv.created_by)}"],
              ["Closed", "-" if draft else f"{_when(inv.concluded_at)} by {_who(data, inv.concluded_by)}"],
              ["Data sources", ", ".join(f"{c['name']} ({c['type']})" for c in data.connections) or "-"],
              ["MITRE ATT&CK", ", ".join(data.techniques) or "none tagged"],
              ["Report generated", _when(data.generated_at)]],
             [32 * mm, 138 * mm], header=False),
        P("1. Hypothesis and conclusion", h2),
        P(f"Hypothesis: {inv.hypothesis}"),
        Spacer(1, 3),
        P(f"Conclusion: {inv.conclusion}" if inv.conclusion else "No conclusion has been recorded yet."),
    ]

    # 2 data coverage
    story.append(P("2. What the data sources could and could not see", h2))
    story.append(P("A hunt that finds nothing in a blind spot means \"could not look\", not \"clean\". Coverage was measured on "
                   "the dates shown.", small))
    rows = [["Source", "Recent events", "Latest event", "Fields with no recent data"]]
    for c in data.connections:
        p = c["profile"]
        if not p:
            rows.append([f"{c['name']} ({c['type']})", "not profiled", "-", "unknown: no data profile was collected"])
        else:
            kind = "" if p.get("recent_docs") else " (archive: no events in the last %s days)" % p.get("window_days")
            rows.append([f"{c['name']} ({c['type']})", f"{p.get('recent_docs', 0):,}{kind}", (p.get("latest") or "-")[:19].replace("T", " "),
                         ", ".join(blind_fields(p)) or ("none" if p.get("recent_docs") else "not judged")])
    story.append(grid(rows, [50 * mm, 40 * mm, 32 * mm, 48 * mm]))

    # 3 timeline
    story.append(P("3. Investigation timeline", h2))
    story.append(P("ORION proposes; an analyst approves each step; only approved steps run.", small))
    if not inv.steps:
        story.append(P("No steps were taken."))
    for step in inv.steps:
        decision = ""
        if step.decided_at:
            ok = step.status in ("approved", "executed", "failed")
            decision = (f"{'Approved' if ok else 'Rejected'} by {_who(data, step.decided_by)}, {_when(step.decided_at)}"
                        + (f': "{step.decision_comment}"' if step.decision_comment else ""))
        block = [
            P(f"Step {step.seq}: {step.title}", ParagraphStyle("st", parent=body, fontName="Helvetica-Bold", spaceBefore=6)),
            P(f"{'Hunt a Sigma rule' if step.kind == 'rule' else 'Pivot on a finding'}  |  {_proposer(step.proposed_by)}  |  status: {step.status}", small),
            P(f"Why: {step.rationale}"),
        ]
        if decision:
            block.append(P(f"Decision: {decision}", small))
        block.append(P(f"Outcome: {_outcome(step)}"))
        story.append(KeepTogether(block))

    # 4 findings
    story.append(P("4. Evidence: findings", h2))
    if not data.findings:
        story.append(P("No hunt step of this investigation produced findings."))
    else:
        story.append(P("One row per behaviour, most important first. Priority is computed by ORION from fixed, listed factors "
                       "(not by the AI).", small))
        rows = [["Prio", "SIEM", "Host", "Process / command", "Seen", "Corroborated", "Analyst"]]
        for f in data.findings:
            rows.append([f.priority_score if f.priority_score is not None else "-", f.siem_type, f.host_name or "-",
                         (f.process_name or f.action or "-") + (f": {f.process_command_line[:70]}" if f.process_command_line else ""),
                         f"{f.occurrence_count}x", ", ".join(c["siem_type"] for c in getattr(f, "corroborated_by", [])) or "no",
                         f.analyst_status])
        story.append(grid(rows, [11 * mm, 15 * mm, 28 * mm, 62 * mm, 14 * mm, 22 * mm, 18 * mm]))
        top = data.findings[0]
        if top.priority_breakdown:
            story.append(Spacer(1, 6))
            story.append(P(f"Why the top finding scores {top.priority_score}/100:", ParagraphStyle("tb", parent=body, fontName="Helvetica-Bold")))
            story.append(grid([["Points", "Factor", "Reason"]] + [[f"{b['points']:+d}", b["factor"], b["detail"]] for b in top.priority_breakdown],
                              [16 * mm, 28 * mm, 126 * mm]))

    # 5 AI involvement
    a = data.ai
    story.append(P("5. Role of the AI and of the analyst", h2))
    approved = sum(1 for s in inv.steps if s.decided_by and s.status in ("approved", "executed", "failed"))
    story.append(P(
        f"{len(inv.steps)} step(s): {a.get('steps_proposed_by_ai', 0)} proposed by the AI planner, {a.get('steps_proposed_by_rules', 0)} "
        f"rule-based suggestion(s), {a.get('steps_added_by_analyst', 0)} added by analysts. {approved} were approved by an analyst and "
        f"run; no step ran without approval. Model calls recorded for this investigation: {a.get('calls', 0)}"
        + (f" ({', '.join(a['models'])})" if a.get("models") else "") + ". Every proposal is validated before an analyst sees it "
        "(the rule must parse, be runnable on a live source, and cite real evidence). Findings, scores and the verdict above are "
        "deterministic or human; the AI only proposes."))

    # 6 limitations
    story.append(P("6. Limitations", h2))
    limits = []
    blind = sorted({f for c in data.connections for f in blind_fields(c["profile"])})
    if blind:
        limits.append("Fields with no recent data on at least one source, so rules depending on them could not be judged there: " + ", ".join(blind) + ".")
    if any(c["type"] == "wazuh" for c in data.connections):
        limits.append("Wazuh holds alerts raised by its own rules, not raw telemetry: an activity no Wazuh rule flagged is invisible to it.")
    if any(not c["profile"] for c in data.connections):
        limits.append("At least one source was never profiled, so its coverage is unknown.")
    limits.append("Sampled telemetry (for example a process snapshot every 30 seconds) can miss short-lived activity.")
    limits.append("Priority weights are heuristic and have not been calibrated against labelled data.")
    for item in limits:
        story.append(P("- " + item))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=_pdf_text(inv.title), author="ORION", pageCompression=1 if compress else 0)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(18 * mm, 11 * mm, _pdf_text(
            f"ORION investigation report{' (DRAFT)' if draft else ''}  |  investigation {inv.id}"))
        canvas.drawString(18 * mm, 7.5 * mm, _pdf_text(f"Contains no credentials. Generated {_when(data.generated_at)}."))
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
