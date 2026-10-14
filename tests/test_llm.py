"""LLM client: provider-neutral, fails fast, and never hangs the planner.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import time
import unittest

from types import SimpleNamespace as NS

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


# [explain] The Gemini model chain: when one model is out of its daily allowance, the next one answers.
class GeminiFallback(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.behaviour = {}                      # model -> exception name to raise, or None to answer
        calls, behaviour = self.calls, self.behaviour

        class FakeGemini:
            def __init__(self, model, **kwargs):
                self.model = model

            def invoke(self, messages):
                calls.append(self.model)
                problem = behaviour.get(self.model)
                if problem:
                    raise type(problem, (Exception,), {})("boom")
                return NS(content=f"answered by {self.model}")

        self.real = llm_module.ChatGoogleGenerativeAI
        llm_module.ChatGoogleGenerativeAI = FakeGemini
        llm_module._exhausted_until.clear()

    def tearDown(self):
        llm_module.ChatGoogleGenerativeAI = self.real
        llm_module._exhausted_until.clear()

    def chain(self, *models):
        return llm_module.GeminiFallbackLLM(list(models), "k", 0.3, 5)

    def test_the_next_model_answers_when_the_first_is_out(self):
        self.behaviour["a"] = "ResourceExhausted"
        llm = self.chain("a", "b", "c")
        self.assertEqual(llm.invoke([HumanMessage(content="x")]).content, "answered by b")
        self.assertEqual(llm.last_model, "b")
        self.assertEqual(self.calls, ["a", "b"])

    def test_an_exhausted_model_is_not_retried_for_a_while(self):
        self.behaviour["a"] = "ResourceExhausted"
        llm = self.chain("a", "b")
        llm.invoke([HumanMessage(content="x")])
        llm.invoke([HumanMessage(content="x")])
        self.assertEqual(self.calls, ["a", "b", "b"])            # the second round skips "a" entirely

    def test_a_missing_model_is_skipped_too(self):
        self.behaviour["a"] = "NotFound"
        self.assertEqual(self.chain("a", "b").invoke([HumanMessage(content="x")]).content, "answered by b")

    def test_a_real_error_is_not_hidden_by_trying_other_models(self):
        self.behaviour["a"] = "InvalidArgument"
        with self.assertRaises(Exception) as ctx:
            self.chain("a", "b").invoke([HumanMessage(content="x")])
        self.assertEqual(type(ctx.exception).__name__, "InvalidArgument")
        self.assertEqual(self.calls, ["a"])

    def test_when_every_model_is_out_the_error_is_raised(self):
        self.behaviour.update({"a": "ResourceExhausted", "b": "ResourceExhausted"})
        with self.assertRaises(Exception) as ctx:
            self.chain("a", "b").invoke([HumanMessage(content="x")])
        self.assertEqual(type(ctx.exception).__name__, "ResourceExhausted")

    def test_get_llm_builds_the_chain_without_duplicates(self):
        s = llm_module.settings
        old = (s.LLM_PROVIDER, s.GEMINI_MODEL, s.GEMINI_FALLBACK_MODELS)
        try:
            s.LLM_PROVIDER, s.GEMINI_MODEL, s.GEMINI_FALLBACK_MODELS = "gemini", "m1", "m2, m1 ,m3"
            self.assertEqual(llm_module.get_llm().models, ["m1", "m2", "m3"])
        finally:
            s.LLM_PROVIDER, s.GEMINI_MODEL, s.GEMINI_FALLBACK_MODELS = old

    def test_the_audit_names_the_model_that_really_answered(self):
        self.behaviour["a"] = "ResourceExhausted"
        s = llm_module.settings
        old = s.LLM_PROVIDER
        s.LLM_PROVIDER = "gemini"
        try:
            _, audit = llm_module.llm_call_with_audit(self.chain("a", "b"), "prompt", "", "test")
        finally:
            s.LLM_PROVIDER = old
        self.assertEqual(audit["model"], "b")


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
