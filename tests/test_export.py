"""Investigation export (notebook + PDF) and the hunt library ranking.

Run:  python -m unittest discover -s tests -t . -v
"""
import ast
import json
import re
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from app.services.investigation.context import rank_similar
from app.services.investigation.export import ExportData, _py_literal, build_notebook, build_report_pdf, slug

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
ANALYST, FINDING = uuid.uuid4(), uuid.uuid4()
RULE = "title: Netcat\nlogsource: {product: linux}\ndetection:\n  selection:\n    Image|endswith: '/nc'\n  condition: selection\n"


def step(seq, kind, status, **kw):
    base = dict(seq=seq, kind=kind, status=status, title=f"Step {seq}", rationale="because", proposed_by="system",
                payload={}, assessment=None, decided_by=ANALYST, decided_at=NOW, decision_comment=None, hunt_id=None,
                result=None, error=None)
    base.update(kw)
    return NS(**base)


def data(status="concluded", steps=None, profile=None):
    steps = steps if steps is not None else [
        step(1, "pivot", "executed", payload={"finding_id": str(FINDING), "pivot": "process", "window_minutes": 15},
             result={"count": 4, "connection_name": "Elastic lab", "window_minutes": 15}),
        step(2, "rule", "executed", proposed_by="analyst", payload={"sigma_rule": RULE},
             result={"hunt_status": "completed", "total_hits": 2}),
        step(3, "pivot", "rejected", decision_comment="too noisy", payload={"finding_id": str(FINDING), "pivot": "host", "window_minutes": 15}),
        step(4, "rule", "proposed", decided_by=None, decided_at=None, payload={"sigma_rule": RULE + "# other"}),
    ]
    inv = NS(id=uuid.uuid4(), title="Possible backdoor", hypothesis="An attacker left a listener.", status=status,
             verdict="inconclusive" if status == "concluded" else None, conclusion="Test listener." if status == "concluded" else None,
             siem_targets=[uuid.uuid4()], created_by=ANALYST, concluded_by=ANALYST, created_at=NOW, concluded_at=NOW, steps=steps)
    return ExportData(inv=inv, people={ANALYST: "Ada Analyst (soc_l2)"}, generated_at=NOW,
                      connections=[{"name": "Elastic lab", "type": "elastic", "active": True, "collected_at": NOW,
                                    "profile": profile or {"recent_docs": 10, "window_days": 7, "latest": "2026-01-01T11:00:00Z",
                                                           "fields": {"process.parent.executable": {"present": 0, "pct": 0.0},
                                                                      "host.name": {"present": 10, "pct": 100.0}}}}],
                      ai={"calls": 0, "models": [], "steps_proposed_by_ai": 0, "steps_proposed_by_rules": 2, "steps_added_by_analyst": 1},
                      techniques=["T1046"])


def pdf_text(pdf: bytes) -> str:
    """Text of an uncompressed ReportLab PDF (literal strings), enough to assert on content."""
    return " ".join(re.findall(r"\((.*?)\) Tj", pdf.decode("latin-1")))


# [explain] Checks the notebook export: valid structure, only approved steps replayed, no passwords, any rule text survives.
class Notebook(unittest.TestCase):
    def test_structure(self):
        nb = build_notebook(data())
        self.assertEqual((nb["nbformat"], nb["nbformat_minor"]), (4, 4))
        json.dumps(nb)                                                # serialisable
        tags = [c["metadata"].get("tags") for c in nb["cells"] if c["cell_type"] == "code"]
        self.assertIn(["parameters"], tags)
        for cell in nb["cells"]:
            if cell["cell_type"] == "code":
                compile("".join(cell["source"]), "cell", "exec")      # every code cell is valid Python
                self.assertEqual((cell["execution_count"], cell["outputs"]), (None, []))

    def test_only_approved_steps_are_replayed(self):
        nb = build_notebook(data())
        code = "\n".join("".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code")
        self.assertIn("RULE_2", code)
        self.assertIn(f'FINDING_1 = "{FINDING}"', code)
        self.assertNotIn("RULE_4", code)                              # never decided
        self.assertNotIn("FINDING_3", code)                           # rejected
        md = "\n".join("".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "markdown")
        self.assertIn("too noisy", md)                                # the rejection is still on record
        self.assertIn("Approved by Ada Analyst (soc_l2)", md)

    def test_no_credentials_only_env_var_names(self):
        text = json.dumps(build_notebook(data()))
        self.assertIn("ORION_EMAIL", text)
        self.assertIn('os.environ[\\"ORION_PASSWORD\\"]', text)
        self.assertNotRegex(text, r"(?i)password\"?\s*[:=]\s*\"[^\"]{3,}")

    def test_rule_text_survives_any_content(self):
        for nasty in (RULE, RULE + "x: '''quotes'''\n", RULE + "path: C:\\\\temp\\\\", "title: 'a'\r\nb: 1\r\n"):
            ns = {}
            exec(f"value = {_py_literal(nasty)}", ns)
            self.assertEqual(ns["value"].strip(), nasty.strip())

    def test_draft_when_open(self):
        nb = build_notebook(data("open"))
        self.assertIn("DRAFT", "".join(nb["cells"][0]["source"]))
        self.assertIn("still open", "".join(nb["cells"][-1]["source"]))


# [explain] Checks the PDF report: content, DRAFT stamp, hostile or non-Latin text, unknown coverage.
class Report(unittest.TestCase):
    def test_concluded_report_content(self):
        pdf = build_report_pdf(data(), compress=False)
        self.assertTrue(pdf.startswith(b"%PDF"))
        text = pdf_text(pdf)
        for expected in ("Possible backdoor", "Verdict: inconclusive", "Step 2", "too noisy", "process.parent.executable",
                         "no step ran without approval", "T1046"):
            self.assertIn(expected, text)

    def test_open_investigation_is_marked_draft(self):
        self.assertIn("DRAFT", pdf_text(build_report_pdf(data("open"), compress=False)))

    def test_hostile_and_non_latin_text_does_not_break_the_report(self):
        d = data()
        d.inv.title = "<b>bold</b> & \u2192 \u4e2d\u6587 <script>alert(1)</script>"
        d.inv.steps[0].rationale = "\u2192 arrow \u2713 check \x00 control"
        pdf = build_report_pdf(d, compress=False)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertNotIn("<script>", pdf.decode("latin-1"))

    def test_unprofiled_source_is_reported_as_unknown(self):
        d = data()
        d.connections[0]["profile"] = None
        self.assertIn("no data profile was collected", pdf_text(build_report_pdf(d, compress=False)))

    def test_compressed_output_is_smaller(self):
        d = data()
        self.assertLess(len(build_report_pdf(d, compress=True)), len(build_report_pdf(d, compress=False)))

    def test_slug(self):
        self.assertEqual(slug("Possible backdoor / listener!"), "possible-backdoor-listener")
        self.assertEqual(slug("???"), "investigation")


# [explain] Checks that similar past investigations are found by word overlap, and unrelated ones are not.
class HuntLibrary(unittest.TestCase):
    def test_similar_hypotheses_rank_first(self):
        candidates = [
            ("a", "netcat listener backdoor on workstation persistence"),
            ("b", "ssh brute force against the bastion"),
            ("c", "backdoor listener opened by netcat"),
        ]
        ranked = rank_similar("possible netcat backdoor listener", candidates, limit=2)
        self.assertEqual(set(ranked), {"a", "c"})
        self.assertNotIn("b", ranked)

    def test_nothing_in_common_means_nothing_offered(self):
        self.assertEqual(rank_similar("kerberoasting service tickets", [("a", "netcat listener")]), [])
        self.assertEqual(rank_similar("", [("a", "netcat listener")]), [])


if __name__ == "__main__":
    unittest.main()
