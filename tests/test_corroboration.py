"""The corroboration shown on a finding lists only the other SIEM types.

Run:  python -m unittest discover -s tests -t . -v
"""
import asyncio
import unittest
from types import SimpleNamespace as NS

from app.services.corroboration import attach_corroboration


class FakeDb:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _query):
        return NS(all=lambda: self.rows)


class Corroboration(unittest.TestCase):
    def test_same_siem_siblings_of_a_chained_group_are_left_out(self):
        # two Elastic findings chained by one Wazuh finding share a correlation id
        rows = [NS(id=1, siem_type="elastic", correlation_id="g"), NS(id=2, siem_type="elastic", correlation_id="g"),
                NS(id=3, siem_type="wazuh", correlation_id="g")]
        findings = [NS(id=1, siem_type="elastic", correlation_id="g"), NS(id=3, siem_type="wazuh", correlation_id="g")]
        asyncio.run(attach_corroboration(FakeDb(rows), findings))
        self.assertEqual([c["siem_type"] for c in findings[0].corroborated_by], ["wazuh"])
        self.assertEqual(sorted(c["id"] for c in findings[1].corroborated_by), [1, 2])

    def test_a_finding_without_group_has_no_corroboration(self):
        findings = [NS(id=9, siem_type="elastic", correlation_id=None)]
        asyncio.run(attach_corroboration(FakeDb([]), findings))
        self.assertEqual(findings[0].corroborated_by, [])


if __name__ == "__main__":
    unittest.main()
