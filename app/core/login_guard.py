"""Throttle password guessing: too many failed logins lock the account name and the source address for a while.

Failures are counted per e-mail (so a distributed guess against one account is slowed) and per client address
(so one machine cannot try many accounts). Unknown e-mails are counted exactly like known ones, so the
lockout does not reveal which accounts exist.

Limit: the counters live in this process's memory. That is right for the single-server deployment of this
project; several workers or servers would each keep their own counters, and a restart clears them.
"""
import time
from typing import Callable, Dict, List

MAX_FAILURES_PER_EMAIL = 5
MAX_FAILURES_PER_ADDRESS = 20
WINDOW_SECONDS = 15 * 60
LOCKOUT_SECONDS = 15 * 60
_MAX_TRACKED_KEYS = 5000


class LoginGuard:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._failures: Dict[str, List[float]] = {}

    def _recent(self, key: str) -> List[float]:
        now = self._clock()
        recent = [t for t in self._failures.get(key, []) if now - t < WINDOW_SECONDS]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def retry_after(self, email: str, address: str) -> int:
        """Seconds until another attempt is allowed; 0 when not locked."""
        waits = []
        for key, limit in ((f"email:{email.strip().lower()}", MAX_FAILURES_PER_EMAIL), (f"addr:{address}", MAX_FAILURES_PER_ADDRESS)):
            recent = self._recent(key)
            if len(recent) >= limit:
                waits.append(int(LOCKOUT_SECONDS - (self._clock() - recent[-1])) + 1)
        return max([w for w in waits if w > 0], default=0)

    def failure(self, email: str, address: str) -> None:
        if len(self._failures) > _MAX_TRACKED_KEYS:          # bound the memory an attacker can make us use
            self._failures.clear()
        now = self._clock()
        for key in (f"email:{email.strip().lower()}", f"addr:{address}"):
            self._failures.setdefault(key, []).append(now)

    def success(self, email: str) -> None:
        self._failures.pop(f"email:{email.strip().lower()}", None)


login_guard = LoginGuard()
