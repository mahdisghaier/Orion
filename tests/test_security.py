"""Security controls of ORION itself: CSRF, login throttling, and the role matrix of every endpoint.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
import uuid
from types import SimpleNamespace as NS

from fastapi.testclient import TestClient

from app.core.csrf import csrf_ok
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.login_guard import LOCKOUT_SECONDS, MAX_FAILURES_PER_ADDRESS, MAX_FAILURES_PER_EMAIL, WINDOW_SECONDS, LoginGuard
from app.main import app

UID = "00000000-0000-0000-0000-000000000001"


class CsrfRules(unittest.TestCase):
    COOKIES = {"access_token": "t", "csrf_token": "abc123"}

    def test_safe_methods_and_login_are_exempt(self):
        self.assertTrue(csrf_ok("GET", "/api/findings/", self.COOKIES, {}))
        self.assertTrue(csrf_ok("POST", "/api/auth/login", {}, {}))
        self.assertTrue(csrf_ok("POST", "/health", self.COOKIES, {}))               # not an API route

    def test_cookie_authenticated_change_needs_the_matching_header(self):
        self.assertFalse(csrf_ok("POST", "/api/findings/x/suppress", self.COOKIES, {}))
        self.assertFalse(csrf_ok("DELETE", "/api/siem/x", self.COOKIES, {"x-csrf-token": "wrong"}))
        self.assertTrue(csrf_ok("PATCH", "/api/findings/x", self.COOKIES, {"x-csrf-token": "abc123"}))

    def test_no_csrf_cookie_means_no_way_to_pass(self):
        self.assertFalse(csrf_ok("POST", "/api/hunts/", {"access_token": "t"}, {"x-csrf-token": "abc"}))
        self.assertFalse(csrf_ok("POST", "/api/hunts/", {"access_token": "t", "csrf_token": ""}, {"x-csrf-token": ""}))

    def test_header_authentication_is_not_csrf_able(self):
        self.assertTrue(csrf_ok("POST", "/api/hunts/", {}, {"authorization": "Bearer x"}))

    def test_odd_input_does_not_crash(self):
        self.assertFalse(csrf_ok("POST", "/api/hunts/", self.COOKIES, {"x-csrf-token": "é中"}))


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class LoginThrottle(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.guard = LoginGuard(self.clock)

    def fail(self, n, email="a@x.io", addr="10.0.0.1"):
        for _ in range(n):
            self.guard.failure(email, addr)

    def test_five_failures_lock_the_account_name(self):
        self.fail(MAX_FAILURES_PER_EMAIL - 1)
        self.assertEqual(self.guard.retry_after("a@x.io", "10.0.0.1"), 0)
        self.fail(1)
        wait = self.guard.retry_after("a@x.io", "10.0.0.1")
        self.assertTrue(0 < wait <= LOCKOUT_SECONDS + 1)

    def test_the_lock_follows_the_account_from_any_address_and_is_case_insensitive(self):
        self.fail(MAX_FAILURES_PER_EMAIL)
        self.assertGreater(self.guard.retry_after("A@X.IO", "203.0.113.9"), 0)

    def test_unknown_accounts_are_throttled_exactly_like_known_ones(self):
        self.fail(MAX_FAILURES_PER_EMAIL, email="nobody@x.io")
        self.assertGreater(self.guard.retry_after("nobody@x.io", "10.0.0.1"), 0)

    def test_one_address_cannot_try_many_accounts(self):
        for i in range(MAX_FAILURES_PER_ADDRESS):
            self.guard.failure(f"user{i}@x.io", "10.0.0.7")
        self.assertGreater(self.guard.retry_after("fresh@x.io", "10.0.0.7"), 0)
        self.assertEqual(self.guard.retry_after("fresh@x.io", "10.0.0.8"), 0)

    def test_the_lock_expires_and_a_success_resets_the_account(self):
        self.fail(MAX_FAILURES_PER_EMAIL)
        self.clock.now += WINDOW_SECONDS + 1
        self.assertEqual(self.guard.retry_after("a@x.io", "10.0.0.1"), 0)
        self.fail(MAX_FAILURES_PER_EMAIL - 1)
        self.guard.success("a@x.io")
        self.fail(1)
        self.assertEqual(self.guard.retry_after("a@x.io", "10.0.0.1"), 0)

    def test_memory_use_is_bounded(self):
        for i in range(6000):
            self.guard.failure(f"u{i}@x.io", f"10.1.{i % 250}.{i % 200}")
        self.assertLess(len(self.guard._failures), 6000)


class FakeDb:
    """Stands in for the database: finds no user, accepts audit lines."""
    def __init__(self):
        self.added = []

    async def execute(self, *a, **k):
        return NS(scalar_one_or_none=lambda: None)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass


class BoomDb:
    """Any use of the database fails: a request that reaches it has passed the role check."""
    async def execute(self, *a, **k):
        raise RuntimeError("database used")

    async def get(self, *a, **k):
        raise RuntimeError("database used")

    def add(self, *a):
        raise RuntimeError("database used")

    async def commit(self):
        raise RuntimeError("database used")


def use_db(db):
    async def override():
        yield db
    app.dependency_overrides[get_db] = override


def act_as(role):
    app.dependency_overrides[get_current_user] = lambda: NS(id=uuid.uuid4(), role=role, is_active=True, email="t@x.io", full_name="T")


def reset():
    app.dependency_overrides.clear()


class LoginEndpoint(unittest.TestCase):
    def tearDown(self):
        reset()

    def test_repeated_failures_end_in_429_with_retry_after(self):
        import app.api.auth as auth_module
        original = auth_module.login_guard
        auth_module.login_guard = LoginGuard()
        try:
            use_db(FakeDb())
            client = TestClient(app)
            codes = [client.post("/api/auth/login", json={"email": "who@x.io", "password": "nope"}).status_code for _ in range(6)]
            self.assertEqual(codes[:MAX_FAILURES_PER_EMAIL], [401] * MAX_FAILURES_PER_EMAIL)
            self.assertEqual(codes[MAX_FAILURES_PER_EMAIL], 429)
            blocked = client.post("/api/auth/login", json={"email": "who@x.io", "password": "nope"})
            self.assertGreater(int(blocked.headers["Retry-After"]), 0)
        finally:
            auth_module.login_guard = original


class CsrfMiddleware(unittest.TestCase):
    def tearDown(self):
        reset()

    def test_cookie_authenticated_post_without_the_header_is_refused_before_any_handler_runs(self):
        use_db(BoomDb())
        act_as("admin")
        client = TestClient(app, raise_server_exceptions=False)
        refused = client.post(f"/api/findings/{UID}/suppress", json={}, cookies={"access_token": "t", "csrf_token": "c1"})
        self.assertEqual(refused.status_code, 403)
        self.assertIn("CSRF", refused.json()["detail"])
        passed = client.post(f"/api/findings/{UID}/suppress", json={}, cookies={"access_token": "t", "csrf_token": "c1"},
                             headers={"X-CSRF-Token": "c1"})
        self.assertNotEqual(passed.status_code, 403)                  # got past the middleware and the role check


class RecordingDb(FakeDb):
    """Like FakeDb, plus what the admin endpoints call before and after writing."""
    def __init__(self, user=None):
        super().__init__()
        self.user = user

    async def execute(self, *a, **k):
        user = self.user
        return NS(scalar_one_or_none=lambda: user, scalars=lambda: NS(all=lambda: []))

    async def flush(self):
        pass

    async def refresh(self, obj):
        pass

    def audit_lines(self):
        return [o for o in self.added if type(o).__name__ == "AuditLog"]


class AuditCoverage(unittest.TestCase):
    """Administrative and security-relevant actions leave an audit line, and that line never carries a secret."""

    def tearDown(self):
        reset()

    def test_creating_a_user_is_audited_without_the_password(self):
        db = RecordingDb()
        use_db(db)
        act_as("admin")
        TestClient(app, raise_server_exceptions=False).post(
            "/api/users/", json={"email": "new@x.io", "full_name": "New", "role": "soc_l1", "password": "Sup3r-Secret-Pw!"})
        lines = db.audit_lines()
        self.assertEqual([l.action for l in lines], ["user.create"])
        self.assertNotIn("Sup3r-Secret-Pw!", str(lines[0].metadata_))
        self.assertEqual(lines[0].metadata_["role"], "soc_l1")

    def test_registering_a_siem_is_audited_without_its_config(self):
        db = RecordingDb()
        use_db(db)
        act_as("admin")
        TestClient(app, raise_server_exceptions=False).post(
            "/api/siem/", json={"name": "lab", "type": "elastic", "config": {"url": "http://e:9200", "api_key": "KEY-VALUE-123"}})
        lines = db.audit_lines()
        self.assertEqual([l.action for l in lines], ["siem.create"])
        self.assertNotIn("KEY-VALUE-123", str(lines[0].metadata_))
        self.assertEqual(lines[0].metadata_, {"name": "lab", "type": "elastic"})

    def test_successful_and_failed_logins_are_both_audited(self):
        import app.api.auth as auth_module
        from app.core.security import hash_password
        original = auth_module.login_guard
        auth_module.login_guard = LoginGuard()
        try:
            user = NS(id=uuid.uuid4(), email="ok@x.io", role="soc_l1", is_active=True, password_hash=hash_password("right-password"))
            db = RecordingDb(user)
            use_db(db)
            client = TestClient(app, raise_server_exceptions=False)
            self.assertEqual(client.post("/api/auth/login", json={"email": "ok@x.io", "password": "right-password"}).status_code, 200)
            self.assertEqual(client.post("/api/auth/login", json={"email": "ok@x.io", "password": "wrong"}).status_code, 401)
            actions = [l.action for l in db.audit_lines()]
            self.assertEqual(actions, ["auth.login", "auth.login_failed"])
            self.assertNotIn("right-password", str([l.metadata_ for l in db.audit_lines()]))
        finally:
            auth_module.login_guard = original


ALL = {"soc_l1", "soc_l2", "soc_l3", "admin"}
L2_UP = {"soc_l2", "soc_l3", "admin"}
ADMIN = {"admin"}

# method, path, roles allowed to reach the handler (the documented role matrix)
MATRIX = [
    ("GET", "/api/auth/me", ALL),
    ("GET", "/api/users/", ADMIN), ("POST", "/api/users/", ADMIN),
    ("GET", f"/api/users/{UID}", ADMIN), ("PATCH", f"/api/users/{UID}", ADMIN),
    ("GET", "/api/siem/", ADMIN), ("POST", "/api/siem/", ADMIN), ("GET", f"/api/siem/{UID}", ADMIN),
    ("POST", f"/api/siem/{UID}/test", ADMIN), ("POST", f"/api/siem/{UID}/profile", ADMIN),
    ("GET", f"/api/siem/{UID}/profile", ALL), ("DELETE", f"/api/siem/{UID}", ADMIN),
    ("GET", "/api/hunts/", ALL), ("POST", "/api/hunts/", ALL), ("GET", f"/api/hunts/{UID}", ALL),
    ("GET", f"/api/hunts/{UID}/results", ALL),
    ("GET", "/api/findings/", ALL), ("GET", f"/api/findings/{UID}", ALL), ("GET", f"/api/findings/{UID}/context", ALL),
    ("PATCH", f"/api/findings/{UID}", L2_UP), ("POST", f"/api/findings/{UID}/escalate", L2_UP),
    ("POST", f"/api/findings/{UID}/suppress", L2_UP), ("DELETE", f"/api/findings/{UID}/suppress", L2_UP),
    ("POST", "/api/sigma/convert", L2_UP),
    ("GET", "/api/investigations/", ALL), ("POST", "/api/investigations/", ALL), ("GET", f"/api/investigations/{UID}", ALL),
    ("POST", f"/api/investigations/{UID}/propose", ALL), ("POST", f"/api/investigations/{UID}/steps", ALL),
    ("POST", f"/api/investigations/{UID}/steps/{UID}/approve", ALL), ("POST", f"/api/investigations/{UID}/steps/{UID}/reject", ALL),
    ("POST", f"/api/investigations/{UID}/conclude", L2_UP),
    ("GET", f"/api/investigations/{UID}/report.pdf", ALL), ("GET", f"/api/investigations/{UID}/notebook", ALL),
]


class RoleMatrix(unittest.TestCase):
    def tearDown(self):
        reset()

    def test_every_endpoint_enforces_exactly_its_documented_roles(self):
        use_db(BoomDb())
        client = TestClient(app, raise_server_exceptions=False)
        wrong = []
        for role in sorted(ALL):
            act_as(role)
            for method, path, allowed in MATRIX:
                status = client.request(method, path, json={}).status_code
                granted = status not in (401, 403)
                if granted != (role in allowed):
                    wrong.append((role, method, path, status))
        self.assertEqual(wrong, [], f"{len(wrong)} role mismatch(es)")

    def test_every_endpoint_refuses_anonymous_callers(self):
        use_db(BoomDb())
        client = TestClient(app, raise_server_exceptions=False)
        open_routes = [(m, p) for m, p, _ in MATRIX if client.request(m, p, json={}).status_code != 401]
        self.assertEqual(open_routes, [])

    def test_the_matrix_covers_every_api_route(self):
        covered = {(m, p.replace(UID, "{id}")) for m, p, _ in MATRIX}
        declared = set()
        for route in app.routes:
            path = getattr(route, "path", "")
            if path.startswith("/api/"):
                import re
                normal = re.sub(r"\{[a-z_]+\}", "{id}", path)
                for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
                    declared.add((method, normal))
        public = {("POST", "/api/auth/login"), ("POST", "/api/auth/refresh"), ("POST", "/api/auth/logout")}
        chat = {m for m in declared if m[1].startswith("/api/chat")}
        missing = sorted(declared - covered - public - chat)
        self.assertEqual(missing, [], "routes with no role test")


if __name__ == "__main__":
    unittest.main()
