"""Elastic connector — Layer 2 (SIEM Connectors).

Executes EQL queries against an Elasticsearch cluster and returns
ECS-normalized events. Per Chapter 3.2: authenticates via API key
(when configured), calls POST /_eql/search with the EQL query in the
request body, uses httpx.AsyncClient for non-blocking I/O.
"""
from typing import List, Optional

import httpx

from app.services.connectors.base import BaseSIEMConnector


class ElasticConnectionError(Exception):
    """Raised when the Elastic cluster is unreachable or returns an error."""
    pass


class ElasticConnector(BaseSIEMConnector):
    """Connector for Elasticsearch / Elastic Security.

    Args:
        cluster_url: Base URL of the cluster, e.g. "http://localhost:9200"
            or "https://<cluster>.es.io" for Elastic Cloud.
        api_key: Optional API key for authentication. Omit for local
            dev clusters with xpack.security.enabled=false.
        index_pattern: Index pattern to query, e.g. "logs-*" or
            "metrics-system.process-*" for our local VM setup.
    """

    siem_type = "elastic"

    def __init__(
        self,
        cluster_url: str,
        api_key: Optional[str] = None,
        index_pattern: str = "metrics-system.process-*",
    ):
        self.cluster_url = cluster_url.rstrip("/")
        self.api_key = api_key
        self.index_pattern = index_pattern

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    async def run_query(
        self,
        query: str,
        max_results: int = 1000,
    ) -> List[dict]:
        """Execute an EQL query, return ECS-normalized events as dicts.

        Raises:
            ElasticConnectionError: on network failure or non-2xx response.
        """
        url = f"{self.cluster_url}/{self.index_pattern}/_eql/search"
        payload = {
            "query": query,
            "size": max_results,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=self._headers())
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ElasticConnectionError(
                f"Elastic query failed ({e.response.status_code}): {e.response.text}"
            ) from e
        except httpx.RequestError as e:
            raise ElasticConnectionError(f"Elastic connection failed: {e}") from e

        data = response.json()
        hits = data.get("hits", {}).get("events", [])

        return [hit.get("_source", {}) for hit in hits]

    async def test_connection(self) -> bool:
        """Health check — confirms the cluster is reachable and responsive."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.cluster_url}/_cluster/health",
                    headers=self._headers(),
                )
                return response.status_code == 200
        except httpx.RequestError:
            return False
