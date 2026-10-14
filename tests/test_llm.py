"""LLM client: provider-neutral, fails fast, and never hangs the planner.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import time
import unittest

import httpx
from langchain_core.messages import HumanMessage, SystemMessage

from app.services.agent import llm as llm_module
from app.services.agent.llm import LLMUnavailable, OpenAICompatLLM
from app.services.investigation.proposer import propose_steps

FINDING = {"id": "f-1", "siem": "elastic", "host": "h", "process": "nc", "command_line": "nc -l 4444",
           "user": "u", "priority": 40, "why": [], "occurrences": 1, "also_reported_by": [], "earlier_hunts": 0,
           "analyst_status": "new"}
CTX = {"siems": [], "findings": [FINDING], "steps_so_far": []}


def client(handler, **kw):
    return OpenAICompatLLM("http://llm.local/v1/", "tiny-model", "k3y", transport=httpx.MockTransport(handler), **kw)


# [explain] The generic AI client fails fast and reports every kind of error.
class OpenAICompat(unittest.TestCase):
    def test_request_shape_and_reply(self):
        seen = {}

        def handler(request):
            seen["url"], seen["auth"], seen["body"] = str(request.url), request.headers["authorization"], json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        reply = client(handler).invoke([SystemMessage(content="be brief"), HumanMessage(content="hi")])
        self.assertEqual(reply.content, "ok")
        self.assertEqual(seen["url"], "http://llm.local/v1/chat/completions")
        self.assertEqual(seen["auth"], "Bearer k3y")
        self.assertEqual(seen["body"]["model"], "tiny-model")
        self.assertEqual([m["role"] for m in seen["body"]["messages"]], ["system", "user"])

    def test_no_authorization_header_without_a_key(self):
        seen = {}

        def handler(request):
            seen["headers"] = dict(request.headers)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        OpenAICompatLLM("http://localhost:11434/v1", "m", transport=httpx.MockTransport(handler)).invoke([HumanMessage(content="x")])
        self.assertNotIn("authorization", seen["headers"])

    def test_quota_and_server_errors_fail_at_once_without_retrying(self):
        calls = []

        def handler(request):
            calls.append(1)
            return httpx.Response(429, text="quota exceeded")

        started = time.monotonic()
        with self.assertRaises(LLMUnavailable) as ctx:
            client(handler).invoke([HumanMessage(content="x")])
        self.assertIn("429", str(ctx.exception))
        self.assertEqual(len(calls), 1)
        self.assertLess(time.monotonic() - started, 2)

    def test_malformed_replies_are_reported_not_crashed_on(self):
        for body in ({"choices": []}, {"oops": 1}):
            with self.assertRaises(LLMUnavailable):
                client(lambda r, b=body: httpx.Response(200, json=b)).invoke([HumanMessage(content="x")])

    def test_network_errors_become_llm_unavailable(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        with self.assertRaises(LLMUnavailable):
            client(handler).invoke([HumanMessage(content="x")])


# [explain] The settings choose the right provider.
class Selection(unittest.TestCase):
    def test_provider_selection_and_identity(self):
        s = llm_module.settings
        old = (s.LLM_PROVIDER, s.LLM_BASE_URL, s.LLM_MODEL)
        try:
            s.LLM_PROVIDER, s.LLM_BASE_URL, s.LLM_MODEL = "openai_compatible", "http://x/v1", "m1"
            self.assertIsInstance(llm_module.get_llm(), OpenAICompatLLM)
            self.assertEqual(llm_module.llm_identity(), ("openai_compatible", "m1"))
            s.LLM_BASE_URL = None
            with self.assertRaises(LLMUnavailable):
                llm_module.get_llm()
            s.LLM_PROVIDER = "gemini"
            self.assertEqual(llm_module.llm_identity()[0], "google")
        finally:
            s.LLM_PROVIDER, s.LLM_BASE_URL, s.LLM_MODEL = old


# [explain] A slow AI is cut off and the rule-based suggestions are returned.
class PlannerNeverHangs(unittest.IsolatedAsyncioTestCase):
    async def test_a_slow_model_is_cut_off_and_the_fallback_is_returned(self):
        def slow(prompt, system, name):
            time.sleep(1.0)
            return "{}", {}

        started = time.monotonic()
        proposal = await propose_steps(CTX, "h", [], set(), llm_call=slow, guard_seconds=0.05)
        self.assertLess(time.monotonic() - started, 0.6)
        self.assertIn("did not answer", proposal.notes[0])
        self.assertTrue(proposal.steps)                       # rule-based suggestions are still there


if __name__ == "__main__":
    unittest.main()
