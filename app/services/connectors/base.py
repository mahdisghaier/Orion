"""Uniform SIEM connector interface — Layer 2 (SIEM Connectors).

Every connector (Sentinel, Elastic, future: Splunk) implements this
same interface so the Hunt Runner (Layer 3/6) can treat every SIEM
identically, per Chapter 3.2 of the architecture brief.
"""
from abc import ABC, abstractmethod
from typing import List


class BaseSIEMConnector(ABC):
    """Uniform interface every SIEM connector implements."""

    siem_type: str  # 'sentinel' | 'elastic'

    @abstractmethod
    async def run_query(
        self,
        query: str,
        max_results: int = 1000,
    ) -> List[dict]:
        """Execute the native query, return ECS-normalized events as dicts."""
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Health check used by admin UI / SIEM connection testing."""
        ...