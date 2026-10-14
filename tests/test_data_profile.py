"""Data profile: what a SIEM can see, and blind-spot detection for a rule.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest

import httpx

from app.services.connectors.elastic import ElasticConnector
from app.services.connectors.wazuh import WazuhConnector
from app.services.data_profile import blind_spots, build_profile, profile_fields


def profile(siem="elastic", recent=100, present=None):
    fields = {f: (present or {}).get(f, recent) for f in profile_fields(siem)}
    return build_profile(siem, 7, total_docs=500, recent_docs=recent, earliest="2026-01-01T00:00:00Z",
                         latest="2026-01-08T00:00:00Z", field_counts=fields, top=[("system.process", 100)])


class Profile(unittest.TestCase):
    def test_profiled_fields_cover_every_mapping_target(self):
        self.assertTrue({"process.executable", "process.parent.executable", "host.name"} <= set(profile_fields("elastic")))
        self.assertTrue({"full_log", "data.command", "agent.name"} <= set(profile_fields("wazuh")))
        self.assertEqual(profile_fields("sentinel"), [])

    def test_percentages(self):
        p = profile(recent=200, present={"process.executable": 50, "user.name": 0})
        self.assertEqual(p["fields"]["process.executable"], {"present": 50, "pct": 25.0})
        self.assertEqual(p["fields"]["user.name"]["pct"], 0.0)
        self.assertEqual(build_profile("elastic", 7, 0, 0, None, None, {"host.name": 0}, [])["fields"]["host.name"]["pct"], 0.0)


class BlindSpots(unittest.TestCase):
    def test_field_with_no_events_is_a_blind_spot(self):
        p = profile(present={"process.parent.executable": 0})
        self.assertEqual(blind_spots({"Image", "ParentImage"}, "elastic", p),
                         ["ParentImage -> process.parent.executable"])

    def test_populated_fields_are_fine_even_when_rare(self):
        p = profile(present={"process.parent.executable": 1})
        self.assertEqual(blind_spots({"ParentImage"}, "elastic", p), [])

    def test_silent_siem_is_never_judged(self):
        # an archive with no recent events may still hold older ones: do not block the hunt
        self.assertEqual(blind_spots({"ParentImage"}, "elastic", profile(recent=0)), [])

    def test_no_profile_or_unmeasured_fields_are_not_judged(self):
        self.assertEqual(blind_spots({"ParentImage"}, "elastic", None), [])
        p = profile()
        del p["fields"]["process.parent.executable"]
        self.assertEqual(blind_spots({"ParentImage"}, "elastic", p), [])
        self.assertEqual(blind_spots({"Unknown"}, "elastic", profile()), [])

    def test_wazuh_blind_spot(self):
        p = profile("wazuh", present={"data.command": 0})
        self.assertEqual(blind_spots({"CommandLine", "Computer"}, "wazuh", p), ["CommandLine -> data.command"])


class ProfileQueries(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def aggs(fields, top_key):
        out = {"earliest": {"value_as_string": "2026-01-01T00:00:00Z"},
               "latest": {"value_as_string": "2026-01-08T00:00:00Z"},
               "recent": {"doc_count": 10, "top": {"buckets": [{"key": top_key, "doc_count": 7}]}}}
        for i, _ in enumerate(fields):
            out["recent"][f"f{i}"] = {"doc_count": 10 if i % 2 == 0 else 0}
        return out

    async def test_elastic_profile(self):
        seen = {}
        fields = profile_fields("elastic")

        def handler(request):
            seen["url"], seen["body"] = str(request.url), json.loads(request.content)
            return httpx.Response(200, json={"hits": {"total": {"value": 42}}, "aggregations": self.aggs(fields, "system.process")})

        import app.services.connectors.elastic as mod
        real = mod.httpx.AsyncClient
        mod.httpx.AsyncClient = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
        try:
            p = await ElasticConnector("http://es:9200", index_pattern="metricbeat-*").profile(3)
        finally:
            mod.httpx.AsyncClient = real
        self.assertEqual(seen["url"], "http://es:9200/metricbeat-*/_search")
        self.assertEqual(seen["body"]["size"], 0)
        self.assertEqual(seen["body"]["aggs"]["recent"]["filter"]["range"]["@timestamp"]["gte"], "now-3d")
        self.assertEqual((p["total_docs"], p["recent_docs"], p["window_days"]), (42, 10, 3))
        self.assertEqual(p["top"], [{"value": "system.process", "count": 7}])
        self.assertEqual(p["fields"][fields[0]]["pct"], 100.0)
        self.assertEqual(p["fields"][fields[1]]["pct"], 0.0)

    async def test_wazuh_profile_counts_alert_kinds(self):
        fields = profile_fields("wazuh")

        def handler(request):
            body = json.loads(request.content)
            self.assertEqual(body["aggs"]["recent"]["aggs"]["top"]["terms"]["field"], "rule.description")
            return httpx.Response(200, json={"hits": {"total": {"value": 9}}, "aggregations": self.aggs(fields, "sudo")})

        c = WazuhConnector("https://wz:9200", "u", "p")
        c._client = lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(handler))
        p = await c.profile()
        self.assertEqual(p["siem_type"], "wazuh")
        self.assertEqual(p["top_label"], "rule.description")


if __name__ == "__main__":
    unittest.main()
