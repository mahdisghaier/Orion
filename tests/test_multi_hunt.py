"""One rule for every client: a separate hunt per client, never a hunt across clients.

Run:  python -m unittest discover -s tests -t . -v
"""
import asyncio
import unittest
import uuid
from types import SimpleNamespace as NS

from app.services.multi_hunt import hunt_every_client

A, B, C = (NS(id=uuid.uuid4(), name=n) for n in ("Client A", "Client B", "Client C"))
CONNECTIONS = {A.id: ["a1", "a2"], B.id: ["b1"], C.id: []}


def go(clients, run):
    async def connections_of(client_id):
        return CONNECTIONS[client_id]
    return asyncio.run(hunt_every_client(clients, connections_of, run))


class EveryClient(unittest.TestCase):
    def test_each_client_gets_its_own_hunt_on_its_own_connections_only(self):
        calls = []

        async def run(client_id, connections):
            calls.append((client_id, list(connections)))
            return NS(id=uuid.uuid4(), status="completed", total_hits=3, error=None)

        results = go([A, B], run)
        self.assertEqual(calls, [(A.id, ["a1", "a2"]), (B.id, ["b1"])])      # never a1 and b1 in one hunt
        self.assertEqual([r.status for r in results], ["completed", "completed"])
        self.assertEqual([r.total_hits for r in results], [3, 3])

    def test_a_client_without_a_connection_is_skipped_and_says_why(self):
        async def run(client_id, connections):
            return NS(id=uuid.uuid4(), status="completed", total_hits=0, error=None)

        results = go([A, C], run)
        self.assertEqual([r.status for r in results], ["completed", "skipped"])
        self.assertIn("no active", results[1].note)

    def test_one_client_failing_does_not_stop_the_others(self):
        async def run(client_id, connections):
            if client_id == A.id:
                raise RuntimeError("SIEM unreachable")
            return NS(id=uuid.uuid4(), status="completed", total_hits=1, error=None)

        results = go([A, B], run)
        self.assertEqual([r.status for r in results], ["failed", "completed"])
        self.assertIn("unreachable", results[0].note)

    def test_the_result_names_the_client(self):
        async def run(client_id, connections):
            return NS(id=uuid.uuid4(), status="completed", total_hits=0, error=None)

        self.assertEqual([r.client_name for r in go([A, B], run)], ["Client A", "Client B"])

    def test_no_client_means_no_hunt(self):
        async def run(client_id, connections):
            raise AssertionError("nothing should run")

        self.assertEqual(go([], run), [])


if __name__ == "__main__":
    unittest.main()
