"""Cross-SIEM correlation: the same behaviour seen by more than one SIEM.

Two findings of one hunt are corroborating when they come from DIFFERENT SIEMs, name the
same host and the same process, and their seen-time spans overlap once each is widened by a
tolerance. The tolerance exists because the sources sample at very different rates (Metricbeat
every 30 s, Wazuh's listening-port check every 360 s), so exact overlap would almost never occur.

Findings stay separate rows (each SIEM keeps its own view of the event); corroborating ones
share a correlation_id. Correlation is transitive (A~B and B~C puts all three together).
Findings without a host or a process name are never correlated: guessing would manufacture
false confidence.
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

# [explain] How far apart in time two SIEMs may be and still count as "the same moment".
# [explain] Metricbeat looks every 30 s but Wazuh's port check only every 6 minutes, so exact timing would never match.
CORRELATION_TOLERANCE = timedelta(minutes=10)


@dataclass
class Candidate:
    siem_type: str
    host: Optional[str]
    process: Optional[str]
    first_seen: datetime
    last_seen: datetime


def _key(c: Candidate):
    if not c.host or not c.process:
        return None
    return (c.host.strip().lower(), c.process.strip().lower())


def _overlap(a: Candidate, b: Candidate, tolerance: timedelta) -> bool:
    return a.first_seen - tolerance <= b.last_seen and b.first_seen - tolerance <= a.last_seen


# [explain] Find findings from DIFFERENT SIEMs that describe the same host + process around the same time and give them one shared id.
# [explain] If A matches B and B matches C, all three are one group (union-find). Missing host or process = never matched (we do not guess).
def correlate(candidates: List[Candidate], tolerance: timedelta = CORRELATION_TOLERANCE) -> List[Optional[str]]:
    """One correlation id (or None) per candidate, in input order."""
    parent = list(range(len(candidates)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    linked = set()
    for i, a in enumerate(candidates):
        key = _key(a)
        if key is None:
            continue
        for j in range(i + 1, len(candidates)):
            b = candidates[j]
            if a.siem_type != b.siem_type and _key(b) == key and _overlap(a, b, tolerance):
                parent[find(i)] = find(j)
                linked.update((i, j))

    ids = {}
    result: List[Optional[str]] = []
    for i in range(len(candidates)):
        if i not in linked:
            result.append(None)
            continue
        root = find(i)
        result.append(ids.setdefault(root, uuid.uuid4().hex[:16]))
    return result
