"""Threat-intelligence feeds: parsing, indicator validation, caching and failure behaviour.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest
from datetime import datetime, timedelta, timezone

import httpx

from app.models import IntelCache
from app.services.threat_intel import feeds

NOW = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)

KEV = {"dateReleased": "2026-01-09", "vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Acme RCE",
     "dateAdded": "2026-01-08", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2025-9999", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "Old", "dateAdded": "2025-01-01",
     "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve", "vendorProject": "x", "product": "y", "vulnerabilityName": "z", "dateAdded": "2026-01-09"},
]}

ATTACK = {"objects": [
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Unix Shell", "x_mitre_platforms": ["Linux", "macOS"],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.004"}]},
    {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Windows only", "x_mitre_platforms": ["Windows"],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1047"}]},
    {"type": "attack-pattern", "id": "attack-pattern--3", "name": "Gone", "revoked": True, "x_mitre_platforms": ["Linux"],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    {"type": "campaign", "id": "campaign--a", "name": "Old campaign", "first_seen": "2019-01-01", "last_seen": "2020-01-01",
     "external_references": [{"source_name": "mitre-attack", "external_id": "C0001"}]},
    {"type": "campaign", "id": "campaign--b", "name": "Recent campaign", "first_seen": "2025-01-01", "last_seen": "2025-12-01",
     "external_references": [{"source_name": "mitre-attack", "external_id": "C0002"}]},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "campaign--a", "target_ref": "attack-pattern--1"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "campaign--b", "target_ref": "attack-pattern--1"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "campaign--b", "target_ref": "attack-pattern--2"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "campaign--b", "target_ref": "attack-pattern--3"},
]}


class Validation(unittest.TestCase):
    def test_only_public_routable_ips_are_indicators(self):
        for good in ("8.8.8.8", "45.33.32.156", "2001:4860:4860::8888"):
            self.assertTrue(feeds.valid_ip(good), good)
        for bad in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "999.1.1.1", "", "evil.com", "1.2.3"):
            self.assertFalse(feeds.valid_ip(bad), bad)

    def test_domains_and_hashes(self):
        self.assertTrue(feeds.valid_domain("Bad.Example.com"))
        for bad in ("localhost", "a", "http://x.com", "x..com", "-bad.com", "bad.c", "a" * 300 + ".com", "x.com/path"):
            self.assertFalse(feeds.valid_domain(bad), bad)
        self.assertTrue(feeds.valid_sha256("a" * 64))
        self.assertFalse(feeds.valid_sha256("a" * 63))
        self.assertFalse(feeds.valid_sha256("g" * 64))


class Parsers(unittest.TestCase):
    def test_kev_keeps_valid_cves_and_the_ransomware_flag(self):
        entries = feeds.parse_kev(KEV)
        self.assertEqual([e["cve"] for e in entries], ["CVE-2026-0001", "CVE-2025-9999"])
        self.assertEqual([e["ransomware"] for e in entries], [True, False])

    def test_new_kev_filters_by_date_newest_first(self):
        entries = feeds.parse_kev(KEV)
        self.assertEqual([e["cve"] for e in feeds.new_kev(entries, datetime(2026, 1, 5, tzinfo=timezone.utc))], ["CVE-2026-0001"])
        self.assertEqual(len(feeds.new_kev(entries, datetime(2020, 1, 1, tzinfo=timezone.utc))), 2)

    def test_attack_is_compacted_and_skips_revoked_objects(self):
        attack = feeds.parse_attack(ATTACK)
        self.assertEqual(sorted(attack["techniques"]), ["T1047", "T1059.004"])         # revoked T9999 is gone
        self.assertEqual({c["name"]: c["techniques"] for c in attack["campaigns"]},
                         {"Old campaign": ["T1059.004"], "Recent campaign": ["T1059.004", "T1047"]})

    def test_recent_campaign_techniques_respects_platform_and_recency(self):
        attack = feeds.parse_attack(ATTACK)
        found = feeds.recent_campaign_techniques(attack, "Linux", campaigns=1)
        self.assertEqual([t["technique"] for t in found], ["T1059.004"])                # Windows-only technique dropped
        self.assertEqual(found[0]["campaigns"], ["Recent campaign"])                    # only the most recent campaign counted
        both = feeds.recent_campaign_techniques(attack, "Linux", campaigns=5)
        self.assertEqual(both[0]["campaigns"], ["Recent campaign", "Old campaign"])     # used by more campaigns ranks first

    def test_feodo_drops_private_and_malformed_addresses(self):
        data = [{"ip_address": "185.220.101.5", "malware": "Emotet", "last_online": "2026-01-01"},
                {"ip_address": "10.1.1.1"}, {"ip_address": "nope"}, {}]
        self.assertEqual([r["ip"] for r in feeds.parse_feodo(data)], ["185.220.101.5"])

    def test_urlhaus_reduces_urls_to_validated_hosts(self):
        text = "# comment\nhttp://91.92.109.43:8080/a.sh\nhttps://Evil.Example.org/x\nhttp://192.168.0.1/x\nhttp://localhost/y\n\nftp://bad..com/z\n"
        parsed = feeds.parse_urlhaus(text)
        self.assertEqual(parsed["ips"], ["91.92.109.43"])
        self.assertEqual(parsed["domains"], ["evil.example.org"])

    def test_indicator_lists_are_capped(self):
        text = "\n".join(f"http://host{i}.example.com/x" for i in range(feeds.MAX_IOCS_PER_KIND + 50))
        self.assertEqual(len(feeds.parse_urlhaus(text)["domains"]), feeds.MAX_IOCS_PER_KIND)


class FakeDb:
    def __init__(self, row=None):
        self.row, self.added = row, []

    async def get(self, model, key):
        return self.row

    def add(self, obj):
        self.added.append(obj)
        self.row = obj

    async def flush(self):
        pass


def client_returning(body, status=200):
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(status, content=body)))


class Caching(unittest.IsolatedAsyncioTestCase):
    async def test_a_fresh_fetch_is_parsed_and_cached(self):
        db = FakeDb()
        payload, meta = await feeds.get_feed(db, "kev", NOW, client_returning(json.dumps(KEV)))
        self.assertEqual(meta["status"], "ok")
        self.assertEqual(len(payload["entries"]), 2)
        self.assertEqual(db.added[0].source, "kev")

    async def test_a_recent_copy_is_used_without_any_request(self):
        db = FakeDb(IntelCache(source="kev", payload={"entries": []}, fetched_at=NOW - timedelta(hours=1)))
        def boom(request):
            raise AssertionError("must not fetch")
        payload, meta = await feeds.get_feed(db, "kev", NOW, httpx.AsyncClient(transport=httpx.MockTransport(boom)))
        self.assertEqual((meta["status"], payload), ("cached", {"entries": []}))

    async def test_a_failed_fetch_falls_back_to_the_old_copy_and_says_so(self):
        db = FakeDb(IntelCache(source="kev", payload={"entries": [1]}, fetched_at=NOW - timedelta(days=3)))
        payload, meta = await feeds.get_feed(db, "kev", NOW, client_returning(b"down", 503))
        self.assertEqual((meta["status"], payload), ("stale", {"entries": [1]}))
        self.assertIn("503", meta["error"])

    async def test_with_nothing_cached_a_failure_is_unavailable_not_empty(self):
        payload, meta = await feeds.get_feed(FakeDb(), "feodo", NOW, client_returning(b"down", 500))
        self.assertIsNone(payload)
        self.assertEqual(meta["status"], "unavailable")

    async def test_garbage_is_a_failure_not_a_crash(self):
        payload, meta = await feeds.get_feed(FakeDb(), "kev", NOW, client_returning(b"<html>not json</html>"))
        self.assertEqual((payload, meta["status"]), (None, "unavailable"))

    async def test_an_oversized_feed_is_refused(self):
        original = feeds.MAX_BYTES["feodo"]
        feeds.MAX_BYTES["feodo"] = 100
        try:
            payload, meta = await feeds.get_feed(FakeDb(), "feodo", NOW, client_returning(b"[" + b" " * 500 + b"]"))
        finally:
            feeds.MAX_BYTES["feodo"] = original
        self.assertEqual(meta["status"], "unavailable")
        self.assertIn("larger", meta["error"])

    async def test_only_allow_listed_sources_exist(self):
        with self.assertRaises(KeyError):
            await feeds.download("http://169.254.169.254/latest/meta-data")

    async def test_epss_enriches_and_failure_means_no_scores(self):
        body = json.dumps({"data": [{"cve": "CVE-2026-0001", "epss": "0.42"}]})
        self.assertEqual(await feeds.epss_scores(["CVE-2026-0001", "bad"], client_returning(body)), {"CVE-2026-0001": 0.42})
        self.assertEqual(await feeds.epss_scores(["CVE-2026-0001"], client_returning(b"x", 500)), {})


if __name__ == "__main__":
    unittest.main()
