"""Uniform SIEM connector interface — Layer 2 (SIEM Connectors).

Every connector (Sentinel, Elastic, future: Splunk) implements this
same interface so the Hunt Runner (Layer 3/6) can treat every SIEM
identically, per Chapter 3.2 of the architecture brief.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional


class BaseSIEMConnector(ABC):
    """Uniform interface every SIEM connector implements."""

    siem_type: str  # 'sentinel' | 'elastic' | 'wazuh'

    @abstractmethod
    async def run_query(
        self,
        query: str,
        max_results: int = 1000,
        time_range: Optional[dict] = None,
    ) -> List[dict]:
        """Execute the native query, return ECS-normalized events as dicts.

        time_range is {"from": ..., "to": ...} (either key optional, ISO or
        date-math values); it bounds @timestamp.
        """
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Health check used by admin UI / SIEM connection testing."""
        ...


    async def fetch_context(
        self,
        kind: str,
        entity: dict,
        start: datetime,
        end: datetime,
        max_results: int = 100,
    ) -> List[dict]:
        """Read-only: events around a finding, for the analyst to pivot on.

        kind is "host", "process" or "user"; entity carries the finding's
        host / process_name / user values. Only fixed, parameterised queries are
        allowed here (no analyst-supplied query text). Returns ECS-shaped events,
        newest first. Connectors that cannot do this keep the default.
        """
        raise NotImplementedError(f"{self.siem_type} connector does not support context pivots")

    async def profile(self, window_days: int = 7) -> dict:
        """Read-only: what this SIEM holds (volume, time coverage, field population, event kinds).

        See services/data_profile.py. Connectors that cannot profile keep the default.
        """
        raise NotImplementedError(f"{self.siem_type} connector does not support profiling")

    async def match_iocs(self, kind: str, values: List[str], start: datetime, end: datetime, max_results: int = 200) -> List[dict]:
        """Read-only: events in the window whose indicator fields contain any of the values (kind: ip, domain, sha256).

        Values are sent as data (a terms filter), never as query text. Returns ECS-shaped events.
        """
        raise NotImplementedError(f"{self.siem_type} connector does not support indicator matching")

    async def find_vulnerabilities(self, cves: List[str], max_results: int = 200) -> List[dict]:
        """Read-only: vulnerability records this SIEM already holds for the given CVE ids (host, package, version)."""
        raise NotImplementedError(f"{self.siem_type} connector holds no vulnerability data")
