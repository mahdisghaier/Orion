"""Elastic connector — Layer 2 (SIEM Connectors).

Executes EQL queries against an Elasticsearch cluster and returns
ECS-normalized events. Per Chapter 3.2: authenticates via API key
(when configured), calls POST /_eql/search with the EQL query in the
request body, uses httpx.AsyncClient for non-blocking I/O.
"""
from datetime import datetime
from typing import List, Optional

import httpx

from app.services.connectors.base import BaseSIEMConnector
from app.services.data_profile import build_profile, profile_fields


class ElasticConnectionError(Exception):
    """Raised when the Elastic cluster is unreachable or returns an error."""
    pass


# [explain] Talks to Elasticsearch over HTTP. Searches use EQL (Elastic's event query language).
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

    # [explain] The HTTP headers, with the API key if one is configured.
    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    # [explain] Sends the EQL search and returns the events (the _source of every hit). Errors become ElasticConnectionError.
    async def run_query(
        self,
        query: str,
        max_results: int = 1000,
        time_range: Optional[dict] = None,
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
        bounds = {}
        if time_range and time_range.get("from"):
            bounds["gte"] = time_range["from"]
        if time_range and time_range.get("to"):
            bounds["lte"] = time_range["to"]
        if bounds:
            payload["filter"] = {"range": {"@timestamp": bounds}}

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

    # [explain] Asks the cluster for its health: reachable and answering = yes.
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

    # [explain] Builds a plain filter search (host, or process on the host, or user) inside a time window. Values go in as data, never as query text.
    async def fetch_context(
        self,
        kind: str,
        entity: dict,
        start: datetime,
        end: datetime,
        max_results: int = 100,
    ) -> List[dict]:
        """Events around a finding: same host, same process on the host, or same user."""
        filters = [{"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}]
        host, process, user = entity.get("host"), entity.get("process_name"), entity.get("user")
        if kind == "host":
            filters.append({"term": {"host.name": host}})
        elif kind == "process":
            filters.append({"term": {"process.name": process}})
            if host:
                filters.append({"term": {"host.name": host}})
        elif kind == "user":
            filters.append({"term": {"user.name": user}})
            if host:
                filters.append({"term": {"host.name": host}})
        else:
            raise ValueError(f"unknown pivot kind: {kind}")

        body = {
            "size": min(max_results, 200),
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": filters}},
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.cluster_url}/{self.index_pattern}/_search", json=body, headers=self._headers())
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ElasticConnectionError(
                f"Elastic context query failed ({e.response.status_code}): {e.response.text[:300]}") from e
        except httpx.RequestError as e:
            raise ElasticConnectionError(f"Elastic connection failed: {e}") from e
        return [hit.get("_source", {}) for hit in response.json().get("hits", {}).get("hits", [])]

    # [explain] One aggregation query: oldest/newest event, and for each field how many recent events have it.
    async def profile(self, window_days: int = 7) -> dict:
        fields = profile_fields(self.siem_type)
        body = {
            "size": 0,
            "track_total_hits": True,
            "aggs": {
                "earliest": {"min": {"field": "@timestamp"}},
                "latest": {"max": {"field": "@timestamp"}},
                "recent": {
                    "filter": {"range": {"@timestamp": {"gte": f"now-{int(window_days)}d"}}},
                    "aggs": {
                        **{f"f{i}": {"filter": {"exists": {"field": f}}} for i, f in enumerate(fields)},
                        "top": {"terms": {"field": "event.dataset", "size": 10}},
                    },
                },
            },
        }
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.cluster_url}/{self.index_pattern}/_search", json=body, headers=self._headers())
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ElasticConnectionError(
                f"Elastic profile query failed ({e.response.status_code}): {e.response.text[:300]}") from e
        except httpx.RequestError as e:
            raise ElasticConnectionError(f"Elastic connection failed: {e}") from e

        data = response.json()
        aggs = data["aggregations"]
        return build_profile(
            self.siem_type, window_days,
            total_docs=data["hits"]["total"]["value"],
            recent_docs=aggs["recent"]["doc_count"],
            earliest=aggs["earliest"].get("value_as_string"),
            latest=aggs["latest"].get("value_as_string"),
            field_counts={f: aggs["recent"][f"f{i}"]["doc_count"] for i, f in enumerate(fields)},
            top=[(b["key"], b["doc_count"]) for b in aggs["recent"]["top"]["buckets"]],
        )
