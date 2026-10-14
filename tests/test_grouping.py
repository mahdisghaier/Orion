"""Grouping of repeated events into findings.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from datetime import datetime, timedelta, timezone

from app.services.ecs import extract_ecs_fields
from app.services.grouping import fingerprint, group_events

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


def proc_event(seconds, pid=100, cmd="nc -l -k 127.0.0.1 4444", host="lab-host", name="nc"):
    ts = (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return {
        "@timestamp": ts,
        "host": {"name": host},
        "user": {"name": "analyst"},
        "process": {"name": name, "executable": f"/usr/bin/{name}", "command_line": cmd, "pid": pid},
    }


def pairs(events):
    return [(e, extract_ecs_fields(e)) for e in events]


# [explain] Many identical events become one finding; different behaviour stays separate.
class Grouping(unittest.TestCase):
    def test_samples_of_one_process_become_one_finding(self):
        # 61 snapshots, 30 s apart, same PID
        events = [proc_event(30 * i) for i in range(61)]
        (group,) = group_events("elastic", pairs(events))
        self.assertEqual(group.count, 61)
        self.assertEqual(group.first_seen, T0)
        self.assertEqual(group.last_seen, T0 + timedelta(seconds=30 * 60))
        self.assertEqual(group.fields["event_time"], group.last_seen)   # representative = newest

    def test_pid_and_time_do_not_split_a_group(self):
        a, b = proc_event(0, pid=1), proc_event(500, pid=2)
        self.assertEqual(len(group_events("elastic", pairs([a, b]))), 1)

    def test_different_behaviour_stays_separate(self):
        events = [proc_event(0), proc_event(30, cmd="nc -l 9999"), proc_event(60, host="other-host")]
        self.assertEqual(len(group_events("elastic", pairs(events))), 3)

    def test_same_event_in_two_siems_has_different_fingerprints(self):
        e = proc_event(0)
        f = extract_ecs_fields(e)
        self.assertNotEqual(fingerprint("elastic", e, f), fingerprint("wazuh", e, f))

    def test_alerts_without_process_are_told_apart_by_message(self):
        def alert(msg):
            return {"@timestamp": "2026-01-01T10:00:00Z", "host": {"name": "h"},
                    "rule": {"id": "510"}, "message": msg}
        groups = group_events("wazuh", pairs([alert("rootcheck A"), alert("rootcheck A"), alert("rootcheck B")]))
        self.assertEqual(sorted(g.count for g in groups), [1, 2])

    def test_newest_group_first(self):
        old, new = proc_event(0, name="aaa"), proc_event(100, name="bbb")
        groups = group_events("elastic", pairs([old, new]))
        self.assertEqual([g.fields["process_name"] for g in groups], ["bbb", "aaa"])


if __name__ == "__main__":
    unittest.main()
