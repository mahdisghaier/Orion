"""Cross-SIEM correlation.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest
from datetime import datetime, timedelta, timezone

from app.services.correlation import Candidate, correlate

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


def c(siem, host="lab-host", process="nc", start=0, end=None):
    end = start if end is None else end
    return Candidate(siem, host, process, T0 + timedelta(seconds=start), T0 + timedelta(seconds=end))


# [explain] Checks when two SIEMs' findings are linked: same host and process, close in time, never the same SIEM twice, never guessed.
class Correlation(unittest.TestCase):
    def test_same_host_process_overlapping_in_two_siems(self):
        elastic = c("elastic", start=0, end=1800)             # sampled for 30 minutes
        wazuh = c("wazuh", start=600)                         # one alert inside that span
        a, b = correlate([elastic, wazuh])
        self.assertIsNotNone(a)
        self.assertEqual(a, b)

    def test_tolerance_bridges_different_sampling_rates(self):
        # Wazuh's check ran 5 minutes after Metricbeat last saw the process
        a, b = correlate([c("elastic", start=0, end=60), c("wazuh", start=60 + 300)])
        self.assertEqual(a, b)
        self.assertIsNotNone(a)

    def test_far_apart_in_time_do_not_correlate(self):
        self.assertEqual(correlate([c("elastic", start=0, end=60), c("wazuh", start=60 + 3 * 3600)]), [None, None])

    def test_same_siem_never_correlates_with_itself(self):
        self.assertEqual(correlate([c("elastic", start=0), c("elastic", start=10, process="nc")]), [None, None])

    def test_different_host_or_process_do_not_correlate(self):
        self.assertEqual(correlate([c("elastic"), c("wazuh", host="other-host")]), [None, None])
        self.assertEqual(correlate([c("elastic"), c("wazuh", process="ncat")]), [None, None])

    def test_host_and_process_compare_case_insensitively(self):
        a, b = correlate([c("elastic", host="Lab-Host", process="NC"), c("wazuh", host="lab-host", process="nc")])
        self.assertIsNotNone(a)
        self.assertEqual(a, b)

    def test_missing_host_or_process_is_never_guessed(self):
        self.assertEqual(correlate([c("elastic", process=None), c("wazuh", process=None)]), [None, None])
        self.assertEqual(correlate([c("elastic", host=None), c("wazuh", host=None)]), [None, None])

    def test_three_sources_chain_into_one_group(self):
        ids = correlate([c("elastic", start=0), c("wazuh", start=100), c("sentinel", start=200)])
        self.assertEqual(len(set(ids)), 1)
        self.assertIsNotNone(ids[0])

    def test_unrelated_pairs_get_different_ids(self):
        ids = correlate([
            c("elastic", process="nc"), c("wazuh", process="nc"),
            c("elastic", process="ssh"), c("wazuh", process="ssh"),
        ])
        self.assertEqual(ids[0], ids[1])
        self.assertEqual(ids[2], ids[3])
        self.assertNotEqual(ids[0], ids[2])

    def test_input_order_is_preserved_with_unmatched_in_between(self):
        ids = correlate([c("elastic"), c("elastic", process="vim"), c("wazuh")])
        self.assertIsNotNone(ids[0])
        self.assertIsNone(ids[1])
        self.assertEqual(ids[0], ids[2])


if __name__ == "__main__":
    unittest.main()
