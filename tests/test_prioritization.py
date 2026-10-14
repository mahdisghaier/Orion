"""Deterministic priority score.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from app.services.prioritization import (
    DEFAULT_TACTIC_POINTS, Signals, normalize_tactic, score,
)


def factor(scored, name):
    return next(p for p in scored.breakdown if p["factor"] == name)


# [explain] Each factor of the priority score, the caps, and that the breakdown always adds up to the total.
class Scoring(unittest.TestCase):
    def test_breakdown_always_explains_the_total(self):
        s = score(Signals("elastic", other_sources=("wazuh",), tactics=("execution",), occurrence_count=64,
                          span_minutes=45))
        self.assertEqual(s.score, sum(p["points"] for p in s.breakdown))
        self.assertEqual({p["factor"] for p in s.breakdown},
                         {"corroboration", "severity", "new", "persistence", "analyst", "sensor"})
        self.assertTrue(all(p["detail"] for p in s.breakdown))

    def test_corroboration_adds_25_and_names_the_other_siem(self):
        solo = score(Signals("elastic"))
        both = score(Signals("elastic", other_sources=("wazuh",)))
        self.assertEqual(both.score - solo.score, 25)
        self.assertIn("wazuh", factor(both, "corroboration")["detail"])

    def test_severity_follows_the_tier_table(self):
        self.assertEqual(factor(score(Signals("elastic", tactics=("credential_access",))), "severity")["points"], 25)
        self.assertEqual(factor(score(Signals("elastic", tactics=("execution",))), "severity")["points"], 18)
        self.assertEqual(factor(score(Signals("elastic", tactics=("discovery",))), "severity")["points"], 8)
        self.assertEqual(factor(score(Signals("elastic")), "severity")["points"], DEFAULT_TACTIC_POINTS)

    def test_the_worst_tactic_counts_and_names_are_normalised(self):
        s = score(Signals("wazuh", tactics=("Discovery", "Privilege Escalation")))
        self.assertEqual(factor(s, "severity")["points"], 18)
        self.assertEqual(normalize_tactic("Command-and-Control"), "command_and_control")

    def test_wazuh_rule_level_can_outrank_a_weak_tactic(self):
        s = score(Signals("wazuh", tactics=("discovery",), event_level=12))
        self.assertEqual(factor(s, "severity")["points"], 24)
        self.assertIn("rule level 12", factor(s, "severity")["detail"])
        self.assertEqual(factor(score(Signals("wazuh", event_level=15)), "severity")["points"], 25)  # capped

    def test_new_versus_repeat(self):
        self.assertEqual(factor(score(Signals("elastic", previous_hunts=0)), "new")["points"], 15)
        self.assertEqual(factor(score(Signals("elastic", previous_hunts=3)), "new")["points"], 0)

    def test_persistence_grows_with_log2_and_is_capped(self):
        self.assertEqual(factor(score(Signals("elastic", occurrence_count=1)), "persistence")["points"], 0)
        self.assertEqual(factor(score(Signals("elastic", occurrence_count=8)), "persistence")["points"], 3)
        self.assertEqual(factor(score(Signals("elastic", occurrence_count=8, span_minutes=40)), "persistence")["points"], 5)
        self.assertEqual(factor(score(Signals("elastic", occurrence_count=100000, span_minutes=999)), "persistence")["points"], 10)

    def test_analyst_history_moves_the_score_both_ways(self):
        # corroborated baseline (50) so the penalties are not hidden by the clamp at 0
        kw = dict(other_sources=("wazuh",))
        base = score(Signals("elastic", **kw)).score
        self.assertEqual(score(Signals("elastic", validated=1, **kw)).score - base, 20)
        self.assertEqual(score(Signals("elastic", false_positive=1, **kw)).score - base, -10)
        self.assertEqual(score(Signals("elastic", false_positive=9, **kw)).score - base, -30)      # capped
        self.assertEqual(score(Signals("elastic", validated=1, false_positive=5, **kw)).score - base, 20)  # confirmation wins
        # the clamp: a bare finding cannot go below 0
        self.assertEqual(score(Signals("elastic", false_positive=9, previous_hunts=3)).score, 0)

    def test_weaker_wazuh_evidence_costs_points(self):
        self.assertEqual(factor(score(Signals("wazuh", derived=True)), "sensor")["points"], -5)
        self.assertEqual(factor(score(Signals("wazuh", has_process=False)), "sensor")["points"], -10)
        self.assertEqual(factor(score(Signals("elastic", has_process=False)), "sensor")["points"], 0)

    def test_suppressed_is_zero_whatever_else_is_true(self):
        s = score(Signals("elastic", other_sources=("wazuh",), tactics=("credential_access",), suppressed=True))
        self.assertEqual(s.score, 0)
        self.assertEqual(s.breakdown[0]["factor"], "suppressed")

    def test_score_is_clamped_and_deterministic(self):
        worst = Signals("wazuh", derived=True, false_positive=9, previous_hunts=5, tactics=("discovery",))
        self.assertGreaterEqual(score(worst).score, 0)
        best = Signals("elastic", other_sources=("wazuh", "sentinel"), tactics=("exfiltration",), validated=2,
                       occurrence_count=10**6, span_minutes=10**4)
        self.assertLessEqual(score(best).score, 100)
        self.assertEqual(score(best), score(best))

    def test_the_lab_listener_ranks_above_a_benign_repeat(self):
        # corroborated, long-lived, discovery tactic, but a repeat across hunts
        listener = score(Signals("elastic", other_sources=("wazuh",), tactics=("discovery",),
                                 previous_hunts=6, occurrence_count=348, span_minutes=36))
        # the same behaviour after an analyst marked it false positive
        benign = score(Signals("elastic", tactics=("discovery",), previous_hunts=6, false_positive=1,
                               occurrence_count=348, span_minutes=36))
        self.assertGreater(listener.score, benign.score)


if __name__ == "__main__":
    unittest.main()
