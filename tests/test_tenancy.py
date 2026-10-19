"""Clients: a user bound to one client never sees, changes or reaches anything of another client.

Run:  python -m unittest discover -s tests -t . -v
"""
import asyncio
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import client_for_new_object, client_of_connections, ensure_visible, scoped, visible
from app.main import app
from app.models import HuntResult, Notification
from app.services.grouping import for_client

A, B = uuid.uuid4(), uuid.uuid4()
UID = "00000000-0000-0000-0000-000000000001"


def user(client=None, role="admin"):
    return NS(id=uuid.uuid4(), role=role, is_active=True, email="t@x.io", full_name="T", client_id=client)


def run(coro):
    return asyncio.run(coro)


class FakeDb:
    """Answers every query with one fixed row (or rows), like a database that holds a single object."""
    def __init__(self, row=None, rows=None):
        self.row, self.rows = row, rows if rows is not None else []

    async def execute(self, *a, **k):
        return NS(scalar_one_or_none=lambda: self.row, scalars=lambda: NS(all=lambda: self.rows), all=lambda: self.rows,
                  scalar=lambda: 0)

    async def get(self, model, key):
        return self.row

    async def commit(self):
        pass


class Visibility(unittest.TestCase):
    def test_a_bound_user_sees_only_their_client(self):
        self.assertTrue(visible(NS(client_id=A), user(A)))
        self.assertFalse(visible(NS(client_id=B), user(A)))
        self.assertFalse(visible(NS(client_id=None), user(A)))          # an unowned row is not visible to a client

    def test_platform_staff_see_every_client(self):
        self.assertTrue(visible(NS(client_id=A), user(None)))
        self.assertTrue(visible(NS(client_id=B), user(None)))

    def test_another_clients_object_answers_404_like_a_missing_one(self):
        with self.assertRaises(HTTPException) as other:
            ensure_visible(NS(client_id=B), user(A), "Finding")
        with self.assertRaises(HTTPException) as missing:
            ensure_visible(None, user(A), "Finding")
        self.assertEqual((other.exception.status_code, other.exception.detail), (missing.exception.status_code, missing.exception.detail))
        self.assertEqual(other.exception.status_code, 404)

    def test_scoped_queries_carry_the_client_condition(self):
        base = select(HuntResult.id)
        self.assertIn("client_id", str(scoped(base, HuntResult.client_id, user(A))))
        self.assertNotIn("client_id", str(scoped(base, HuntResult.client_id, user(None))))
        self.assertIn("client_id", str(scoped(base, HuntResult.client_id, user(None), client=B)))

    def test_a_bound_user_cannot_widen_the_scope_with_a_parameter(self):
        sql = scoped(select(HuntResult.id), HuntResult.client_id, user(A), client=B).compile().params
        self.assertEqual(list(sql.values()), [A])


class NewObjects(unittest.TestCase):
    def test_a_bound_user_creates_for_their_own_client_only(self):
        self.assertEqual(run(client_for_new_object(FakeDb(), user(A))), A)
        self.assertEqual(run(client_for_new_object(FakeDb(), user(A), A)), A)
        with self.assertRaises(HTTPException) as e:
            run(client_for_new_object(FakeDb(), user(A), B))
        self.assertEqual(e.exception.status_code, 403)

    def test_connections_of_one_client_give_that_client(self):
        c1, c2 = uuid.uuid4(), uuid.uuid4()
        db = FakeDb(rows=[(c1, A), (c2, A)])
        self.assertEqual(run(client_of_connections(db, user(A), [c1, c2])), A)
        self.assertEqual(run(client_of_connections(db, user(None), [c1, c2])), A)

    def test_a_connection_of_another_client_is_not_found(self):
        c1 = uuid.uuid4()
        with self.assertRaises(HTTPException) as e:
            run(client_of_connections(FakeDb(rows=[(c1, B)]), user(A), [c1]))
        self.assertEqual(e.exception.status_code, 404)

    def test_an_unknown_connection_is_not_found(self):
        with self.assertRaises(HTTPException) as e:
            run(client_of_connections(FakeDb(rows=[]), user(A), [uuid.uuid4()]))
        self.assertEqual(e.exception.status_code, 404)

    def test_one_hunt_never_mixes_clients(self):
        c1, c2 = uuid.uuid4(), uuid.uuid4()
        with self.assertRaises(HTTPException) as e:
            run(client_of_connections(FakeDb(rows=[(c1, A), (c2, B)]), user(None), [c1, c2]))
        self.assertEqual(e.exception.status_code, 422)

    def test_a_requested_client_must_match_the_connections(self):
        c1 = uuid.uuid4()
        with self.assertRaises(HTTPException) as e:
            run(client_of_connections(FakeDb(rows=[(c1, A)]), user(None), [c1], requested=B))
        self.assertEqual(e.exception.status_code, 422)


class Fingerprints(unittest.TestCase):
    def test_the_same_behaviour_of_two_clients_has_two_fingerprints(self):
        self.assertNotEqual(for_client("abc", A), for_client("abc", B))
        self.assertEqual(for_client("abc", A), for_client("abc", A))

    def test_without_a_client_the_fingerprint_is_unchanged(self):
        self.assertEqual(for_client("abc", None), "abc")


FOREIGN = NS(client_id=B)
ROUTES = [
    ("GET", f"/api/findings/{UID}"), ("GET", f"/api/findings/{UID}/context"), ("PATCH", f"/api/findings/{UID}"),
    ("POST", f"/api/findings/{UID}/suppress"), ("DELETE", f"/api/findings/{UID}/suppress"), ("POST", f"/api/findings/{UID}/escalate"),
    ("GET", f"/api/hunts/{UID}"), ("GET", f"/api/hunts/{UID}/results"),
    ("GET", f"/api/investigations/{UID}"), ("POST", f"/api/investigations/{UID}/propose"),
    ("GET", f"/api/investigations/{UID}/report.pdf"), ("GET", f"/api/investigations/{UID}/notebook"),
    ("GET", f"/api/siem/{UID}"), ("POST", f"/api/siem/{UID}/test"), ("POST", f"/api/siem/{UID}/profile"), ("DELETE", f"/api/siem/{UID}"),
    ("GET", f"/api/jobs/{UID}/runs"), ("PATCH", f"/api/jobs/{UID}"), ("DELETE", f"/api/jobs/{UID}"), ("POST", f"/api/jobs/{UID}/run"),
    ("POST", f"/api/notifications/{UID}/acknowledge"), ("GET", f"/api/users/{UID}"), ("PATCH", f"/api/users/{UID}"),
]


class CrossClientAccess(unittest.TestCase):
    """Every endpoint that takes an identifier answers 404 when the object belongs to another client."""

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_a_client_user_gets_404_for_the_objects_of_another_client(self):
        async def foreign_db():
            yield FakeDb(row=FOREIGN)

        app.dependency_overrides[get_db] = foreign_db
        app.dependency_overrides[get_current_user] = lambda: user(A, "admin")
        http = TestClient(app, raise_server_exceptions=False)
        not_hidden = [(m, p, http.request(m, p, json={}).status_code) for m, p in ROUTES
                      if http.request(m, p, json={}).status_code != 404]
        self.assertEqual(not_hidden, [])

    def test_only_a_platform_wide_admin_creates_clients(self):
        app.dependency_overrides[get_current_user] = lambda: user(A, "admin")
        http = TestClient(app, raise_server_exceptions=False)
        self.assertEqual(http.post("/api/clients/", json={"name": "Other"}).status_code, 403)
        self.assertEqual(http.patch(f"/api/clients/{UID}", json={"name": "x"}).status_code, 403)

    def test_a_client_administrator_cannot_create_users_of_another_client(self):
        async def db():
            yield FakeDb()

        app.dependency_overrides[get_db] = db
        app.dependency_overrides[get_current_user] = lambda: user(A, "admin")
        http = TestClient(app, raise_server_exceptions=False)
        response = http.post("/api/users/", json={"email": "n@x.io", "full_name": "N", "role": "soc_l1",
                                                   "password": "Another-Pw-123", "client_id": str(B)})
        self.assertEqual(response.status_code, 403)


class OwnAccount(unittest.TestCase):
    def tearDown(self):
        app.dependency_overrides.clear()

    def test_an_administrator_cannot_disable_or_demote_their_own_account(self):
        me = user(None, "admin")

        async def db():
            yield FakeDb(row=me)

        app.dependency_overrides[get_db] = db
        app.dependency_overrides[get_current_user] = lambda: me
        http = TestClient(app, raise_server_exceptions=False)
        self.assertEqual(http.patch(f"/api/users/{me.id}", json={"is_active": False}).status_code, 400)
        self.assertEqual(http.patch(f"/api/users/{me.id}", json={"role": "soc_l1"}).status_code, 400)


class NotificationsAndJobs(unittest.TestCase):
    def test_a_job_notification_carries_the_clients_id(self):
        from app.services.threat_intel.runner import _notification
        run_ = NS(summary={"headline": "h", "limits": []}, status="clear", id=uuid.uuid4())
        job = NS(client_id=A)
        self.assertEqual(_notification(run_, job).client_id, A)

    def test_a_clients_job_only_prepares_that_clients_connections(self):
        from app.services.threat_intel.runner import Deps, _prepare_connections
        seen = []

        class Db:
            async def flush(self):
                pass

            async def execute(self, query, *a, **k):
                seen.append(str(query))
                return NS(scalars=lambda: NS(all=lambda: []), scalar_one_or_none=lambda: None)

        run(_prepare_connections(Db(), Deps(), A))
        run(_prepare_connections(Db(), Deps(), None))
        self.assertIn("client_id", seen[0].split("WHERE")[1])
        self.assertNotIn("client_id", seen[1].split("WHERE")[1])


if __name__ == "__main__":
    unittest.main()
