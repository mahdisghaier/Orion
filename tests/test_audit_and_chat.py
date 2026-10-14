"""The audit line joins the caller's transaction; chat helpers; AI-down classification.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
import uuid
from types import SimpleNamespace as NS

from app.api.chat import _ai_unavailable, _save_audits
from app.core.audit import log_action


class FakeSession:
    """Records what is added and committed, without a database."""

    def __init__(self):
        self.added, self.commits = [], 0

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1


class AuditJoinsTheTransaction(unittest.IsolatedAsyncioTestCase):
    async def test_log_action_adds_but_does_not_commit(self):
        db = FakeSession()
        await log_action(db, user_id=uuid.uuid4(), action="finding.update", metadata={"x": 1})
        self.assertEqual(len(db.added), 1)
        self.assertEqual(db.added[0].action, "finding.update")
        self.assertEqual(db.commits, 0)

    async def test_request_details_are_captured_when_present(self):
        db = FakeSession()
        request = NS(client=NS(host="10.0.0.5"), headers={"User-Agent": "x" * 900})
        await log_action(db, user_id=None, action="a", request=request)
        self.assertEqual(db.added[0].ip_address, "10.0.0.5")
        self.assertEqual(len(db.added[0].user_agent), 500)          # bounded


class ChatHelpers(unittest.TestCase):
    ENTRY = {"context": "explain_findings", "prompt": "p" * 9000, "system_prompt": "s" * 2000, "response": "r" * 20000,
             "model": "m", "provider": "google", "latency_ms": 12}

    def test_audits_are_saved_bounded_and_linked_to_the_hunt(self):
        db, hunt = FakeSession(), uuid.uuid4()
        _save_audits(db, NS(id=uuid.uuid4()), [self.ENTRY, self.ENTRY], hunt)
        self.assertEqual(len(db.added), 2)
        row = db.added[0]
        self.assertEqual(row.hunt_id, hunt)
        self.assertEqual((len(row.prompt), len(row.raw_response)), (5000, 10000))
        self.assertEqual(db.commits, 0)                              # the caller commits

    def test_no_entries_adds_nothing(self):
        db = FakeSession()
        _save_audits(db, NS(id=uuid.uuid4()), [])
        self.assertEqual(db.added, [])

    def test_ai_down_errors_are_recognised_by_class_name(self):
        ResourceExhausted = type("ResourceExhausted", (Exception,), {})
        self.assertTrue(_ai_unavailable(ResourceExhausted("quota")))
        self.assertTrue(_ai_unavailable(type("LLMUnavailable", (Exception,), {})("x")))
        self.assertFalse(_ai_unavailable(ValueError("a bug of ours")))        # real bugs are not hidden as "AI down"


if __name__ == "__main__":
    unittest.main()
