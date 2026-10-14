"""Context pivots: the queries are fixed templates built only from the finding's own values.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest
from datetime import datetime, timezone

import httpx

from app.services.connectors.elastic import ElasticConnector
from app.services.connectors.wazuh import WazuhConnector

START = datetime(2026, 1, 1, 9, 45, tzinfo=timezone.utc)
END = datetime(2026, 1, 1, 10, 15, tzinfo=timezone.utc)
ENTITY = {"host": "lab-host", "process_name": "nc", "user": "analyst"}


def patch_httpx(monkeypatch_target, handler):
    """Route every httpx.AsyncClient created by the code under test to a mock transport."""
    real = httpx.AsyncClient
    monkeypatch_target.AsyncClient = lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
    return real


# [explain] The Elastic look-around query is a fixed template and never builds query text from user input.
class ElasticContext(unittest.IsolatedAsyncioTestCase):
    async def run_pivot(self, kind):
        seen = {}

        def handler(request):
            seen["url"], seen["body"] = str(request.url), json.loads(request.content)
            return httpx.Response(200, json={"hits": {"hits": [{"_source": {"host": {"name": "lab-host"}}}]}})

        import app.services.connectors.elastic as mod
        real = patch_httpx(mod.httpx, handler)
        try:
            events = await ElasticConnector("http://es:9200", index_pattern="metricbeat-*").fetch_context(
                kind, ENTITY, START, END, 5000)
        finally:
            mod.httpx.AsyncClient = real
        return seen, events

    async def test_host_pivot(self):
        seen, events = await self.run_pivot("host")
        self.assertEqual(seen["url"], "http://es:9200/metricbeat-*/_search")
        filters = seen["body"]["query"]["bool"]["filter"]
        self.assertIn({"term": {"host.name": "lab-host"}}, filters)
        self.assertEqual(seen["body"]["size"], 200)                      # capped
        self.assertEqual(seen["body"]["sort"], [{"@timestamp": "desc"}])
        self.assertEqual(len(events), 1)

    async def test_process_pivot_is_scoped_to_the_host(self):
        seen, _ = await self.run_pivot("process")
        filters = seen["body"]["query"]["bool"]["filter"]
        self.assertIn({"term": {"process.name": "nc"}}, filters)
        self.assertIn({"term": {"host.name": "lab-host"}}, filters)

    async def test_user_pivot(self):
        seen, _ = await self.run_pivot("user")
        self.assertIn({"term": {"user.name": "analyst"}}, seen["body"]["query"]["bool"]["filter"])

    async def test_unknown_pivot_rejected(self):
        with self.assertRaises(ValueError):
            await ElasticConnector("http://es:9200").fetch_context("raw-query", ENTITY, START, END)

    async def test_values_are_never_interpolated_into_query_text(self):
        evil = {"host": 'x" or 1==1 //', "process_name": "nc", "user": "u"}
        seen = {}

        def handler(request):
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"hits": {"hits": []}})

        import app.services.connectors.elastic as mod
        real = patch_httpx(mod.httpx, handler)
        try:
            await ElasticConnector("http://es:9200").fetch_context("host", evil, START, END)
        finally:
            mod.httpx.AsyncClient = real
        self.assertIn({"term": {"host.name": 'x" or 1==1 //'}}, seen["body"]["query"]["bool"]["filter"])


# [explain] The same for Wazuh, including agent aliases.
class WazuhContext(unittest.IsolatedAsyncioTestCase):
    def connector(self, handler, aliases=None):
        c = WazuhConnector("https://wz:9200", "u", "p", host_aliases=aliases)
        c._client = lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(handler), auth=c._auth)
        return c

    def test_agent_names_include_aliased_agents(self):
        c = WazuhConnector("https://wz", "u", "p", host_aliases={"wsl-ubuntu": "desktop", "other": "x"})
        self.assertEqual(c._agent_names("desktop"), ["desktop", "wsl-ubuntu"])
        self.assertEqual(c._agent_names(None), [])

    async def test_host_pivot_matches_agent_case_insensitively(self):
        seen = {}

        def handler(request):
            seen["body"] = json.loads(request.content)
            alert = {"@timestamp": "2026-01-01T10:00:00Z", "agent": {"name": "wsl-ubuntu"},
                     "rule": {"id": "5403", "description": "sudo"}, "full_log": "x"}
            return httpx.Response(200, json={"hits": {"hits": [{"_source": alert}]}})

        c = self.connector(handler, aliases={"wsl-ubuntu": "desktop"})
        events = await c.fetch_context("host", {"host": "desktop"}, START, END)
        should = seen["body"]["query"]["bool"]["filter"][1]["bool"]["should"]
        self.assertEqual([s["term"]["agent.name"]["value"] for s in should], ["desktop", "wsl-ubuntu"])
        self.assertTrue(all(s["term"]["agent.name"]["case_insensitive"] for s in should))
        self.assertEqual(events[0]["host"]["name"], "desktop")           # alias applied

    async def test_process_pivot_uses_token_match_on_full_log(self):
        seen = {}

        def handler(request):
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"hits": {"hits": []}})

        await self.connector(handler).fetch_context("process", ENTITY, START, END)
        self.assertIn({"match": {"full_log": "nc"}}, seen["body"]["query"]["bool"]["filter"])


if __name__ == "__main__":
    unittest.main()
