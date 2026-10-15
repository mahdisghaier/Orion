"""Threat-intelligence checks: rule library, coverage, indicator logic, verdicts, whole runs with fake SIEMs and feeds.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import httpx

from app.services.connectors.elastic import ElasticConnector
from app.services.connectors.wazuh import WazuhConnector
from app.services.data_profile import build_profile, profile_fields
from app.services.sigma_engine import convert_sigma_rule, unmapped_fields
from app.services.threat_intel import iocs
from app.services.threat_intel.coverage import matrix, navigator_layer, rule_status
from app.services.threat_intel.report import build_intel_report_pdf
from app.services.threat_intel.rules import RULES, library, rules_for, technique_of
from app.services.threat_intel.runner import Deps, Live, clean_custom_iocs, decide, run_job

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def profile(siem="elastic", blind=(), recent=100, drop=()):
    counts = {f: (0 if f in blind else 50) for f in profile_fields(siem) if f not in drop}
    return build_profile(siem, 7, recent, recent, "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", counts, [])


class RuleLibrary(unittest.TestCase):
    def test_every_rule_is_valid_tagged_and_converts_for_both_siems(self):
        self.assertGreaterEqual(len(RULES), 10)
        techniques = []
        for rule in library():
            self.assertRegex(rule["technique"], r"^T\d{4}(\.\d{3})?$")
            techniques.append(rule["technique"])
            converted = convert_sigma_rule(rule["yaml"])
            self.assertTrue(converted["eql"] and converted["lucene"], rule["title"])
            for siem in ("elastic", "wazuh"):
                self.assertEqual(unmapped_fields(rule["yaml"], siem), [], rule["title"])
        self.assertEqual(len(techniques), len(set(techniques)), "one rule per technique")

    def test_rules_are_not_so_broad_that_they_fire_on_ordinary_shells(self):
        for rule in RULES:
            text = rule.lower()
            self.assertNotIn("endswith:\n      - '/bash'", text)
            self.assertNotIn("endswith:\n      - '/sh'", text)

    def test_lookup_by_technique_matches_exact_and_parent(self):
        self.assertEqual([r["technique"] for r in rules_for("T1059.004")], ["T1059.004"])
        self.assertEqual(rules_for("T1105.001")[0]["technique"], "T1105")          # a sub-technique falls back to its parent rule
        self.assertEqual(rules_for("T0000"), [])
        self.assertEqual(technique_of("title: x\ntags: [attack.t1046]\n"), "T1046")


class RuleStatus(unittest.TestCase):
    NC = next(r["yaml"] for r in library() if r["technique"] == "T1046")
    FILE = next(r["yaml"] for r in library() if r["technique"] == "T1565.001")

    def test_each_status(self):
        self.assertEqual(rule_status(self.NC, "elastic", profile())[0], "runnable")
        self.assertEqual(rule_status(self.NC, "elastic", None)[0], "unknown")
        self.assertEqual(rule_status(self.NC, "elastic", profile(recent=0))[0], "archive")
        self.assertEqual(rule_status(self.FILE, "elastic", profile(blind=("file.path",)))[0], "blind")
        self.assertEqual(rule_status(self.NC, "sentinel", profile())[0], "not_runnable")

    def test_a_profile_that_never_measured_the_field_is_not_runnable_by_default(self):
        status, reasons = rule_status(self.FILE, "elastic", profile(drop=("file.path",)))
        self.assertEqual(status, "unknown")
        self.assertIn("never measured file.path", reasons[0])

    def test_matrix_and_navigator_layer(self):
        conns = [{"name": "A", "type": "elastic", "profile": profile(blind=("file.path",))},
                 {"name": "W", "type": "wazuh", "profile": profile("wazuh")}]
        result = matrix(conns)
        self.assertEqual(result["summary"]["rules"], len(RULES))
        file_row = next(r for r in result["rows"] if r["technique"] == "T1565.001")
        self.assertEqual([c["status"] for c in file_row["cells"]], ["blind", "runnable"])
        layer = navigator_layer(result)
        self.assertEqual(layer["versions"]["layer"], "4.5")
        scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        self.assertEqual(scores["T1565.001"], 50)                    # runnable on one of two SIEMs
        self.assertEqual(scores["T1046"], 100)
        json.dumps(layer)


class IndicatorLogic(unittest.TestCase):
    def test_check_status_distinguishes_blind_from_checkable(self):
        self.assertEqual(iocs.check_status("ip", "elastic", profile())[0], "checkable")
        self.assertEqual(iocs.check_status("ip", "elastic", profile(blind=("source.ip", "destination.ip")))[0], "blind")
        self.assertEqual(iocs.check_status("domain", "wazuh", profile("wazuh"))[0], "blind")      # Wazuh has no domain field
        self.assertEqual(iocs.check_status("sha256", "wazuh", profile("wazuh"))[0], "checkable")
        self.assertEqual(iocs.check_status("ip", "elastic", None)[0], "unknown")
        self.assertEqual(iocs.check_status("ip", "elastic", profile(recent=0))[0], "archive")
        self.assertEqual(iocs.check_status("ip", "elastic", profile(drop=("source.ip", "destination.ip")))[0], "unknown")

    def test_matched_indicators_reads_ecs_paths_case_insensitively(self):
        event = {"destination": {"ip": "45.33.32.156"}, "file": {"hash": {"sha256": "AB" * 32}}, "url": {"domain": "Evil.Example.com"}}
        self.assertEqual(iocs.matched_indicators(event, "ip", {"45.33.32.156"}), ["45.33.32.156"])
        self.assertEqual(iocs.matched_indicators(event, "sha256", {"ab" * 32}), ["ab" * 32])
        self.assertEqual(iocs.matched_indicators(event, "domain", {"evil.example.com"}), ["evil.example.com"])
        self.assertEqual(iocs.matched_indicators(event, "ip", {"1.2.3.4"}), [])

    def test_custom_indicators_are_validated_but_may_be_internal(self):
        cleaned = clean_custom_iocs({"ip": ["10.0.0.5", "bad", "0.0.0.0", "10.0.0.5"], "domain": ["Evil.com", "x"], "sha256": ["a" * 64, "short"]})
        self.assertEqual(cleaned, {"ip": ["10.0.0.5"], "domain": ["evil.com"], "sha256": ["a" * 64]})


class FakeSiem:
    """A connector double: records what it was asked and answers from scripted data."""
    def __init__(self, events=None, vulns=None, vuln_records=0):
        self.events, self.vulns, self.vuln_records, self.asked = events or {}, vulns or [], vuln_records, []

    async def match_iocs(self, kind, values, start, end, max_results=200):
        self.asked.append((kind, len(values)))
        return [e for e in self.events.get(kind, [])]

    async def vulnerability_records(self):
        return self.vuln_records

    async def find_vulnerabilities(self, cves, max_results=200):
        return [v for v in self.vulns if v["cve"] in cves]


class FakeDb:
    def __init__(self):
        self.added, self.commits = [], 0

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for o in self.added:
            if getattr(o, "id", None) is None:
                o.id = uuid.uuid4()

    async def commit(self):
        self.commits += 1


ATTACK = {"techniques": {"T1046": {"name": "Network Service Discovery", "tactics": ["discovery"], "platforms": ["Linux"]},
                         "T1070.003": {"name": "Clear Command History", "tactics": ["defense-evasion"], "platforms": ["Linux"]},
                         "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "platforms": ["Linux"]}},
          "campaigns": [{"id": "C1", "name": "Campaign One", "first_seen": "2025-01-01", "last_seen": "2026-01-01",
                         "techniques": ["T1046", "T1070.003", "T1190"]}]}
KEV = {"entries": [{"cve": "CVE-2026-0001", "vendor": "Acme", "product": "Gateway", "name": "RCE", "added": "2026-02-27", "ransomware": True},
                   {"cve": "CVE-2020-0002", "vendor": "Old", "product": "Thing", "name": "x", "added": "2020-01-01", "ransomware": False}]}
FEODO = {"entries": [{"ip": "45.33.32.156", "malware": "Emotet", "last_online": "2026-02-28"}]}
URLHAUS = {"ips": ["91.92.109.43"], "domains": ["evil.example.com"]}


def feed_loader(overrides=None):
    data = {"kev": KEV, "attack": ATTACK, "feodo": FEODO, "urlhaus": URLHAUS}
    data.update(overrides or {})

    async def load(db, source):
        payload = data.get(source)
        return payload, {"source": source, "status": "ok" if payload else "unavailable", "fetched_at": NOW.isoformat(),
                         "error": None if payload else "ConnectError: down"}
    return load


def live(name="Elastic lab", siem="elastic", connector=None, prof=None, error=None):
    return Live(uuid.uuid4(), name, siem, connector or FakeSiem(), prof if prof is not None else profile(siem), error)


def make_deps(lives, feeds_override=None, hunt_findings=0, hunts=None):
    async def connections(db):
        return lives

    async def hunt(db, created_by, ids, rule_yaml, time_range):
        (hunts if hunts is not None else []).append((created_by, ids, time_range))
        return NS(id=uuid.uuid4(), total_hits=hunt_findings, error=None)

    async def top(db, hunt_obj):
        return [{"id": "f1", "siem": "elastic", "host": "h", "process": "nc", "priority": 40}] if hunt_findings else []

    async def admin(db):
        return uuid.uuid4()

    async def epss(cves):
        return {"CVE-2026-0001": 0.91}

    return Deps(load_feed=feed_loader(feeds_override), epss=epss, hunt=hunt, connections=connections, admin_id=admin,
                top_findings=top, now=lambda: NOW)


def new_job(**kw):
    return NS(id=uuid.uuid4(), name="Daily check", interval_hours=24, config=kw.get("config", {}), last_run_at=kw.get("last_run_at"),
              next_run_at=None, created_by=uuid.uuid4())


class WholeRuns(unittest.IsolatedAsyncioTestCase):
    async def test_clear_run_reports_clear_with_every_limit_spelled_out(self):
        hunts = []
        elastic = live(connector=FakeSiem(vuln_records=0))
        wazuh = live("Wazuh lab", "wazuh", FakeSiem(vuln_records=0), profile("wazuh"))
        db, job = FakeDb(), new_job()
        run = await run_job(db, job, "schedule", make_deps([elastic, wazuh], hunts=hunts))
        self.assertEqual(run.status, "clear")
        s = run.summary
        self.assertEqual(s["technique_hunts"]["campaign_techniques"], 3)
        self.assertEqual([h["technique"] for h in s["technique_hunts"]["no_rule"]], ["T1190"])      # no rule for it: stated, not cleared
        self.assertEqual({h["technique"] for h in s["technique_hunts"]["executed"]}, {"T1046", "T1070.003"})
        self.assertEqual(len(hunts), 2)
        joined = " ".join(s["limits"])
        self.assertIn("1 of 3 campaign techniques have no ORION rule", joined)
        self.assertIn("CVE exposure not checked", joined)
        self.assertNotIn("could not be checked on any SIEM", joined)        # Elastic can check domains, so that is not a gap
        self.assertEqual(job.next_run_at, NOW + timedelta(hours=24))
        note = db.added[-1]
        self.assertEqual((note.severity, note.kind), ("info", "threat_intel"))
        self.assertIn("within scope", note.title)
        self.assertIn("Not checked:", note.body)

    async def test_a_technique_hit_makes_the_run_a_finding(self):
        run = await run_job(FakeDb(), new_job(), "manual", make_deps([live()], hunt_findings=2))
        self.assertEqual(run.status, "findings")
        self.assertIn("hit(s) on 2 technique rule(s)", run.summary["headline"])
        self.assertEqual(run.summary["technique_hunts"]["executed"][0]["top"][0]["priority"], 40)

    async def test_an_indicator_match_is_found_where_the_data_exists(self):
        siem = FakeSiem(events={"ip": [{"destination": {"ip": "45.33.32.156"}, "host": {"name": "web-1"}, "@timestamp": "2026-02-28T10:00:00Z"}]})
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live(connector=siem)]))
        self.assertEqual(run.status, "findings")
        match = run.summary["ioc"]["matches"][0]
        self.assertEqual((match["indicator"], match["host"], match["kind"]), ("45.33.32.156", "web-1", "ip"))
        self.assertIn(("ip", 2), siem.asked)                                 # feodo + urlhaus addresses, sent in one batch

    async def test_a_siem_without_the_data_is_not_asked_and_is_reported_blind(self):
        blind = live(connector=FakeSiem(), prof=profile(blind=("source.ip", "destination.ip")))
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([blind]))
        ip_check = next(c for c in run.summary["ioc"]["checks"] if c["kind"] == "ip")
        self.assertEqual(ip_check["status"], "blind")
        self.assertEqual([c for c in blind.connector.asked if c[0] == "ip"], [])        # never asked about addresses
        self.assertTrue(any("ip indicator(s) could not be checked on any SIEM" in x for x in run.summary["limits"]))

    async def test_exposure_to_an_exploited_cve_is_a_finding(self):
        wazuh_siem = FakeSiem(vuln_records=5, vulns=[{"cve": "CVE-2020-0002", "host": "srv-1", "package": "libthing", "version": "1.0", "severity": "High"}])
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live("Wazuh lab", "wazuh", wazuh_siem, profile("wazuh"))]))
        self.assertEqual(run.status, "findings")
        exposure = run.summary["kev"]["exposure"]
        self.assertEqual((exposure["status"], exposure["matches"][0]["host"]), ("checked", "srv-1"))

    async def test_indicators_no_connected_siem_can_look_for_are_named(self):
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live("Wazuh lab", "wazuh", FakeSiem(), profile("wazuh"))]))
        self.assertTrue(any("domain indicator(s) could not be checked on any SIEM" in x for x in run.summary["limits"]))

    async def test_an_empty_vulnerability_index_means_not_checked_never_clear(self):
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live("Wazuh lab", "wazuh", FakeSiem(vuln_records=0), profile("wazuh"))]))
        self.assertEqual(run.summary["kev"]["exposure"]["status"], "not_checked")
        self.assertIn("holds no vulnerability records", run.summary["kev"]["exposure"]["reason"])

    async def test_an_unavailable_required_feed_makes_the_run_incomplete(self):
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live()], feeds_override={"kev": None}))
        self.assertEqual(run.status, "incomplete")
        self.assertIn("kev feed could not be read", " ".join(run.summary["limits"]))

    async def test_no_reachable_siem_is_incomplete_not_clear(self):
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live(error="unreachable (ConnectError)")]))
        self.assertEqual(run.status, "incomplete")
        self.assertIn("no SIEM could be reached", run.summary["headline"])

    async def test_an_archive_is_not_used_to_conclude_anything(self):
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live(prof=profile(recent=0))]))
        self.assertEqual(run.status, "incomplete")
        self.assertFalse(run.summary["connections"][0]["live"])

    async def test_a_crash_is_recorded_as_an_error_and_still_notifies(self):
        deps = make_deps([live()])

        async def boom(db, source):
            raise RuntimeError("disk on fire")
        deps.load_feed = boom
        db = FakeDb()
        run = await run_job(db, new_job(), "schedule", deps)
        self.assertEqual(run.status, "error")
        self.assertIn("disk on fire", run.error)
        self.assertEqual(db.added[-1].title, "Threat-intel check failed")

    async def test_custom_indicators_are_swept_too(self):
        siem = FakeSiem(events={"sha256": [{"file": {"hash": {"sha256": "ab" * 32}}, "host": {"name": "h"}}]})
        wz = live("Wazuh lab", "wazuh", siem, profile("wazuh"))
        job = new_job(config={"custom_iocs": {"sha256": ["ab" * 32]}})
        run = await run_job(FakeDb(), job, "manual", make_deps([wz]))
        self.assertEqual(run.status, "findings")
        self.assertEqual(run.summary["ioc"]["custom"]["sha256"], 1)

    async def test_the_window_starts_at_the_last_run(self):
        hunts = []
        last = NOW - timedelta(hours=30)
        await run_job(FakeDb(), new_job(last_run_at=last), "schedule", make_deps([live()], hunts=hunts))
        self.assertEqual(hunts[0][2]["from"], last.isoformat().replace("+00:00", "Z"))


class Verdict(unittest.TestCase):
    def base(self):
        return {"feeds": {"kev": {"status": "ok", "fetched_at": NOW.isoformat()}, "attack": {"status": "ok", "fetched_at": NOW.isoformat()}},
                "connections": [{"name": "E", "live": True, "error": None}],
                "technique_hunts": {"campaign_techniques": 2, "executed": [], "no_rule": [], "blind": []},
                "ioc": {"counts": {}, "checks": [], "matches": []},
                "kev": {"exposure": {"status": "checked", "reason": "", "matches": []}}}

    def test_clear_findings_and_incomplete(self):
        self.assertEqual(decide(self.base())[0], "clear")
        s = self.base()
        s["ioc"]["matches"] = [{"indicator": "x"}]
        self.assertEqual(decide(s)[0], "findings")
        s = self.base()
        s["feeds"]["attack"]["status"] = "unavailable"
        self.assertEqual(decide(s)[0], "incomplete")

    def test_a_stale_feed_is_named_but_does_not_block_a_clear_verdict(self):
        s = self.base()
        s["feeds"]["kev"] = {"status": "stale", "fetched_at": "2026-02-01T00:00:00+00:00"}
        status, _, limits = decide(s)
        self.assertEqual(status, "clear")
        self.assertTrue(any("could not be refreshed" in x for x in limits))

    def test_findings_beat_missing_data(self):
        s = self.base()
        s["feeds"]["kev"]["status"] = "unavailable"
        s["technique_hunts"]["executed"] = [{"findings": 1}]
        self.assertEqual(decide(s)[0], "findings")


def pdf_text(pdf: bytes) -> str:
    import re
    return " ".join(re.findall(r"\((.*?)\) Tj", pdf.decode("latin-1")))


class ReportPdf(unittest.IsolatedAsyncioTestCase):
    async def test_clear_report_leads_with_the_limits(self):
        run = await run_job(FakeDb(), new_job(), "schedule", make_deps([live()]))
        pdf = build_intel_report_pdf("Daily check", run, NOW, compress=False)
        self.assertTrue(pdf.startswith(b"%PDF"))
        text = pdf_text(pdf)
        self.assertIn("NOTHING FOUND, WITHIN THE LIMITS BELOW", text)
        self.assertIn("could NOT be checked", text)
        self.assertIn("CVE-2026-0001", text)                           # the new exploited CVE, with its EPSS score
        self.assertIn("0.91", text)
        self.assertIn("Exposure NOT checked", text)

    async def test_findings_report_lists_the_match(self):
        siem = FakeSiem(events={"ip": [{"destination": {"ip": "45.33.32.156"}, "host": {"name": "web-1"}}]})
        run = await run_job(FakeDb(), new_job(), "manual", make_deps([live(connector=siem)]))
        text = pdf_text(build_intel_report_pdf("Daily check", run, NOW, compress=False))
        self.assertIn("POSSIBLE MATCH FOUND", text)
        self.assertIn("45.33.32.156", text)


class Transport:
    def __init__(self, response):
        self.seen, self.response = {}, response

    def handler(self, request):
        self.seen["url"], self.seen["body"] = str(request.url), json.loads(request.content) if request.content else None
        return self.response(request) if callable(self.response) else self.response


class ConnectorQueries(unittest.IsolatedAsyncioTestCase):
    START, END = NOW - timedelta(days=1), NOW

    async def test_elastic_sends_indicators_as_a_terms_filter_not_text(self):
        t = Transport(httpx.Response(200, json={"hits": {"hits": [{"_source": {"destination": {"ip": "1.2.3.4"}}}]}}))
        import app.services.connectors.elastic as mod
        real = mod.httpx.AsyncClient
        mod.httpx.AsyncClient = lambda **kw: real(transport=httpx.MockTransport(t.handler), **kw)
        try:
            events = await ElasticConnector("http://es:9200", index_pattern="logs-*").match_iocs("ip", ["1.2.3.4", 'x" or 1==1'], self.START, self.END)
        finally:
            mod.httpx.AsyncClient = real
        should = t.seen["body"]["query"]["bool"]["should"]
        self.assertEqual({list(c["terms"])[0] for c in should}, {"source.ip", "destination.ip"})
        self.assertIn('x" or 1==1', should[0]["terms"][list(should[0]["terms"])[0]])        # a value, never interpolated
        self.assertEqual(len(events), 1)
        self.assertEqual(await ElasticConnector("http://es:9200").match_iocs("ip", [], self.START, self.END), [])

    async def test_wazuh_uses_only_fields_it_has_and_returns_ecs_events(self):
        alert = {"@timestamp": "2026-03-01T10:00:00Z", "agent": {"name": "wsl"}, "rule": {"id": "554", "description": "File added"},
                 "syscheck": {"path": "/tmp/x", "event": "added", "sha256_after": "ab" * 32}}
        t = Transport(httpx.Response(200, json={"hits": {"hits": [{"_source": alert}]}}))
        c = WazuhConnector("https://wz:9200", "u", "p")
        c._client = lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(t.handler))
        events = await c.match_iocs("sha256", ["ab" * 32], self.START, self.END)
        self.assertEqual([list(x["terms"])[0] for x in t.seen["body"]["query"]["bool"]["should"]], ["syscheck.sha256_after"])
        self.assertEqual(events[0]["file"]["hash"]["sha256"], "ab" * 32)
        self.assertEqual(await c.match_iocs("domain", ["evil.com"], self.START, self.END), [])      # Wazuh has no domain field

    async def test_wazuh_vulnerability_queries(self):
        doc = {"vulnerability": {"id": "CVE-2020-0002", "severity": "High"}, "agent": {"name": "srv"}, "package": {"name": "libx", "version": "1.0"}}
        t = Transport(httpx.Response(200, json={"hits": {"hits": [{"_source": doc}]}}))
        c = WazuhConnector("https://wz:9200", "u", "p")
        c._client = lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(t.handler))
        found = await c.find_vulnerabilities(["CVE-2020-0002"])
        self.assertEqual(found, [{"cve": "CVE-2020-0002", "host": "srv", "package": "libx", "version": "1.0", "severity": "High"}])
        self.assertIn("wazuh-states-vulnerabilities", t.seen["url"])
        missing = WazuhConnector("https://wz:9200", "u", "p")
        missing._client = lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
        self.assertEqual(await missing.find_vulnerabilities(["CVE-2020-0002"]), [])
        self.assertEqual(await missing.vulnerability_records(), 0)


if __name__ == "__main__":
    unittest.main()
