"""Wazuh connector — Layer 2 (SIEM Connectors).

The Wazuh indexer is OpenSearch, so there is no _eql endpoint: the Sigma rule is
converted to a Lucene query_string and sent to POST /<index>/_search. Hits are
Wazuh alerts, which are mapped to ECS-shaped events by wazuh_ecs.
"""
from datetime import datetime
from typing import List, Optional

import httpx

from app.services.connectors.base import BaseSIEMConnector
from app.services.connectors.wazuh_ecs import query_process_names, wazuh_to_ecs_events

_MAX_WINDOW = 1000


class WazuhConnectionError(Exception):
    """Raised when the Wazuh indexer is unreachable or returns an error."""
    pass


class WazuhConnector(BaseSIEMConnector):
    """Connector for the Wazuh indexer.

    Args:
        url: e.g. "https://localhost:9201"
        username / password: indexer credentials (from the encrypted SIEM config)
        verify_ssl: False accepts the self-signed lab certificate
        index_pattern: alert indices, default "wazuh-alerts-*"
        host_aliases: optional {wazuh agent name: host name} so a finding lines up with
            the host name another SIEM reports for the same machine
    """

    siem_type = "wazuh"

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        index_pattern: str = "wazuh-alerts-*",
        host_aliases: Optional[dict] = None,
    ):
        self.url = url.rstrip("/")
        self._auth = (username, password)
        self.verify_ssl = verify_ssl
        self.index_pattern = index_pattern
        self.host_aliases = host_aliases or {}

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(auth=self._auth, verify=self.verify_ssl, timeout=timeout)

    @staticmethod
    def _range_filter(time_range: Optional[dict]) -> list:
        if not time_range:
            return []
        bounds = {}
        if time_range.get("from"):
            bounds["gte"] = time_range["from"]
        if time_range.get("to"):
            bounds["lte"] = time_range["to"]
        return [{"range": {"@timestamp": bounds}}] if bounds else []

    async def run_query(
        self,
        query: str,
        max_results: int = 1000,
        time_range: Optional[dict] = None,
    ) -> List[dict]:
        """Run a Lucene query, return ECS-shaped events (not raw alerts).

        Raises:
            WazuhConnectionError: on network failure or non-2xx response.
        """
        body = {
            "size": min(max_results, _MAX_WINDOW),
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [{"query_string": {
                        "query": query,
                        "analyze_wildcard": True,
                        "default_operator": "AND",
                    }}],
                    "filter": self._range_filter(time_range),
                }
            },
        }

        try:
            async with self._client(30.0) as client:
                response = await client.post(f"{self.url}/{self.index_pattern}/_search", json=body)
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise WazuhConnectionError(
                f"Wazuh query failed ({e.response.status_code}): {e.response.text[:300]}"
            ) from e
        except httpx.RequestError as e:
            raise WazuhConnectionError(f"Wazuh connection failed: {type(e).__name__}: {e}") from e

        name_filter = query_process_names(query)
        events: List[dict] = []
        for hit in response.json().get("hits", {}).get("hits", []):
            events.extend(wazuh_to_ecs_events(hit.get("_source", {}), self.host_aliases, name_filter))
        return events[:max_results]

    async def test_connection(self) -> bool:
        """Health check — reachable, authenticated, and cluster not red."""
        try:
            async with self._client(10.0) as client:
                response = await client.get(f"{self.url}/_cluster/health")
                return response.status_code == 200 and response.json().get("status") != "red"
        except (httpx.RequestError, ValueError):
            return False

    def _agent_names(self, host: Optional[str]) -> List[str]:
        """Wazuh agent names that stand for a host name: the name itself plus any aliased to it."""
        if not host:
            return []
        names = [host] + [agent for agent, alias in self.host_aliases.items() if alias == host]
        return list(dict.fromkeys(names))

    async def fetch_context(
        self,
        kind: str,
        entity: dict,
        start: datetime,
        end: datetime,
        max_results: int = 100,
    ) -> List[dict]:
        """Alerts around a finding: same host (agent), same process name in the alert text, or same user."""
        host, process, user = entity.get("host"), entity.get("process_name"), entity.get("user")
        filters = [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]

        if host:
            filters.append({"bool": {"minimum_should_match": 1, "should": [
                {"term": {"agent.name": {"value": name, "case_insensitive": True}}}
                for name in self._agent_names(host)
            ]}})
        if kind == "process":
            filters.append({"match": {"full_log": process}})      # full_log is tokenised text
        elif kind == "user":
            filters.append({"bool": {"minimum_should_match": 1, "should": [
                {"term": {"data.srcuser": user}}, {"term": {"data.dstuser": user}}]}})
        elif kind != "host":
            raise ValueError(f"unknown pivot kind: {kind}")

        body = {
            "size": min(max_results, 200),
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": filters}},
        }
        try:
            async with self._client(30.0) as client:
                response = await client.post(f"{self.url}/{self.index_pattern}/_search", json=body)
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise WazuhConnectionError(
                f"Wazuh context query failed ({e.response.status_code}): {e.response.text[:300]}") from e
        except httpx.RequestError as e:
            raise WazuhConnectionError(f"Wazuh connection failed: {type(e).__name__}: {e}") from e

        events: List[dict] = []
        for hit in response.json().get("hits", {}).get("hits", []):
            events.extend(wazuh_to_ecs_events(hit.get("_source", {}), self.host_aliases))
        return events[:max_results]
