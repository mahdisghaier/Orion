"""PDF report of one threat-intelligence run.

Built only from the stored run summary. A "clear" report is deliberately as detailed as a "findings" one: what was checked,
what could not be checked and why, so nobody reads "clear" as "safe".
"""
import io
from datetime import datetime, timezone
from typing import Optional

from app.services.investigation.export import _pdf_text

VERDICT_TEXT = {
    "findings": "POSSIBLE MATCH FOUND",
    "clear": "NOTHING FOUND, WITHIN THE LIMITS BELOW",
    "incomplete": "INCOMPLETE: NO CONCLUSION POSSIBLE",
    "error": "THE CHECK FAILED",
}


def _when(value) -> str:
    if not value:
        return "-"
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_intel_report_pdf(job_name: str, run, generated_at: Optional[datetime] = None, compress: bool = True) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    generated_at = generated_at or datetime.now(timezone.utc)
    s = run.summary or {}
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#444444"))
    h1 = ParagraphStyle("h1", parent=base["Heading1"], fontSize=18, leading=22, textColor=colors.HexColor("#142840"))
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, leading=16, spaceBefore=14, textColor=colors.HexColor("#1a4a7a"))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)
    colour = {"findings": "#b91c1c", "clear": "#166534", "incomplete": "#b45309", "error": "#b45309"}.get(run.status, "#333333")
    verdict_style = ParagraphStyle("verdict", parent=body, fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor(colour))

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

    story = [
        P("ORION  |  Threat-intelligence check", small),
        P(job_name, h1),
        P(VERDICT_TEXT.get(run.status, run.status.upper()), verdict_style),
        P(s.get("headline", ""), body),
        Spacer(1, 4),
        grid([["Run started", _when(run.started_at)], ["Window checked", f"{_when(s.get('window', {}).get('from'))}  to  {_when(s.get('window', {}).get('to'))}"],
              ["Triggered by", run.trigger], ["Report generated", _when(generated_at)]], [34 * mm, 136 * mm], header=False),
    ]

    limits = s.get("limits") or []
    story.append(P("1. What could NOT be checked", h2))
    story.append(P("Read this before reading \"nothing found\": an indicator or technique that no SIEM could look at is not cleared.", small))
    story += [P("- " + item) for item in limits] or [P("Nothing was left unchecked.")]

    hunts = s.get("technique_hunts", {})
    story.append(P("2. Threat-informed hunt: techniques of recent campaigns", h2))
    story.append(P(f"{hunts.get('campaign_techniques', 0)} Linux techniques are used by recent ATT&CK campaigns; ORION has a rule for "
                   f"{hunts.get('with_rule', 0)} of them.", small))
    if hunts.get("executed"):
        rows = [["Technique", "Rule", "Run on", "Findings", "Used by"]]
        rows += [[h["technique"] + " " + h["name"], h["rule"], ", ".join(h["siems"]), h["findings"], ", ".join(h["campaigns"])] for h in hunts["executed"]]
        story.append(grid(rows, [38 * mm, 42 * mm, 42 * mm, 14 * mm, 34 * mm]))
        for h in hunts["executed"]:
            for top in h.get("top", []):
                story.append(P(f"  {h['technique']}: {top['siem']} finding on {top.get('host') or '?'} ({top.get('process') or 'no process'}), priority {top.get('priority')}", small))
    else:
        story.append(P("No rule could be run for any technique."))
    if hunts.get("no_rule"):
        story.append(Spacer(1, 4))
        story.append(P("Techniques with no ORION rule (not hunted):", ParagraphStyle("b", parent=body, fontName="Helvetica-Bold")))
        story.append(grid([["Technique", "Used by"]] + [[f"{t['technique']} {t['name']}", ", ".join(t["campaigns"])] for t in hunts["no_rule"][:25]], [80 * mm, 90 * mm]))

    ioc = s.get("ioc", {})
    story.append(P("3. Indicator sweep", h2))
    counts = ioc.get("counts", {})
    story.append(P(f"Indicators loaded: {counts.get('ip', 0)} addresses, {counts.get('domain', 0)} domains, {counts.get('sha256', 0)} file hashes "
                   f"({sum((ioc.get('custom') or {}).values())} supplied by the analyst).", small))
    if ioc.get("checks"):
        story.append(grid([["Kind", "SIEM", "Could it check?", "Matches", "Why not / fields used"]] +
                          [[c["kind"], c["connection"], c["status"], c["matches"], "; ".join(c["reasons"]) or ", ".join(c["fields"])] for c in ioc["checks"]],
                          [16 * mm, 44 * mm, 24 * mm, 16 * mm, 70 * mm]))
    if ioc.get("matches"):
        story.append(Spacer(1, 4))
        story.append(P("Matches:", ParagraphStyle("b2", parent=body, fontName="Helvetica-Bold")))
        story.append(grid([["Indicator", "Kind", "SIEM", "Host", "Time"]] +
                          [[m["indicator"], m["kind"], m["connection"], m.get("host") or "-", m.get("time") or "-"] for m in ioc["matches"]],
                          [50 * mm, 16 * mm, 44 * mm, 34 * mm, 26 * mm]))

    kev = s.get("kev", {})
    story.append(P("4. Actively exploited vulnerabilities (CISA KEV)", h2))
    exposure = kev.get("exposure", {})
    if exposure.get("status") == "checked":
        story.append(P(f"Exposure check ran. {len(exposure.get('matches', []))} host(s) carry a CVE from the exploited list."))
        if exposure.get("matches"):
            story.append(grid([["CVE", "Host", "Package", "Version", "SIEM"]] +
                              [[m["cve"], m.get("host") or "-", m.get("package") or "-", m.get("version") or "-", m["connection"]] for m in exposure["matches"][:30]],
                              [30 * mm, 38 * mm, 42 * mm, 30 * mm, 30 * mm]))
    else:
        story.append(P(f"Exposure NOT checked: {exposure.get('reason', 'unknown')}."))
    story.append(P(f"{kev.get('total', 0)} CVEs are on the list; {len(kev.get('new', []))} were added in the window.", small))
    if kev.get("new"):
        story.append(grid([["CVE", "Product", "Added", "Ransomware use", "EPSS"]] +
                          [[e["cve"], f"{e['vendor']} {e['product']}", e["added"], "yes" if e["ransomware"] else "no",
                            f"{e['epss']:.2f}" if e.get("epss") is not None else "-"] for e in kev["new"]], [28 * mm, 70 * mm, 22 * mm, 26 * mm, 16 * mm]))

    story.append(P("5. Sources", h2))
    story.append(grid([["Feed", "Status", "Fetched", "Items"]] +
                      [[n, m["status"] + (f" ({m['error']})" if m.get("error") else ""), _when(m.get("fetched_at")), m.get("items") if m.get("items") is not None else "-"]
                       for n, m in (s.get("feeds") or {}).items()], [24 * mm, 80 * mm, 40 * mm, 26 * mm]))
    story.append(Spacer(1, 4))
    story.append(grid([["SIEM", "Type", "Used", "Recent events", "Note"]] +
                      [[c["name"], c["type"], "yes" if c["live"] else "no", c.get("recent_events") if c.get("recent_events") is not None else "-",
                        c.get("error") or ("archive: no recent events" if not c["live"] else "")] for c in s.get("connections", [])],
                      [60 * mm, 20 * mm, 14 * mm, 28 * mm, 48 * mm]))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="Threat-intelligence check", author="ORION", pageCompression=1 if compress else 0)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(18 * mm, 9 * mm, _pdf_text(f"ORION threat-intelligence check  |  run {run.id}  |  contains no credentials"))
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
