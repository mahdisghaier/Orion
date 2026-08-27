"""Hunt Runner — Layer 3/6. Orchestrates the full hunt flow."""
import asyncio
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID
import yaml

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Hunt, HuntResult, SIEMConnection, SigmaRule
from app.services.connectors.factory import get_connector, ConnectorError
from app.services.ecs import extract_ecs_fields, extract_mitre_from_tags
from app.services.sigma_engine import convert_sigma_rule


class HuntRunnerError(Exception):
    pass


class HuntRunner:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_and_run(
        self,
        created_by: UUID,
        siem_targets: List[UUID],
        rule_id: Optional[UUID] = None,
        rule_yaml: Optional[str] = None,
        time_range: Optional[dict] = None,
    ) -> Hunt:
        # 1. Resolve the Sigma rule YAML
        if rule_id:
            rule = (await self.db.execute(
                select(SigmaRule).where(SigmaRule.id == rule_id)
            )).scalar_one_or_none()
            if not rule:
                raise HuntRunnerError(f"Sigma rule {rule_id} not found")
            rule_yaml = rule.yaml
            mitre_tactics = rule.mitre_tactics or []
            mitre_techniques = rule.mitre_techniques or []
        elif rule_yaml:
            try:
                parsed = yaml.safe_load(rule_yaml)
                tags = parsed.get("tags", []) if parsed else []
                mitre_tactics, mitre_techniques = extract_mitre_from_tags(tags)
            except Exception:
                mitre_tactics, mitre_techniques = [], []
        else:
            raise HuntRunnerError("Either rule_id or rule_yaml must be provided")

        # 2. Convert Sigma → KQL + EQL
        conversion = convert_sigma_rule(rule_yaml)
        queries = {}
        if conversion.get("kql"):
            queries["sentinel"] = conversion["kql"]
        if conversion.get("eql"):
            queries["elastic"] = conversion["eql"]

        if not queries:
            errors = []
            if conversion.get("kql_error"):
                errors.append(f"KQL: {conversion['kql_error']}")
            if conversion.get("eql_error"):
                errors.append(f"EQL: {conversion['eql_error']}")
            raise HuntRunnerError(f"Sigma conversion failed: {'; '.join(errors)}")

        # 3. Create the hunt record
        hunt = Hunt(
            rule_id=rule_id,
            created_by=created_by,
            siem_targets=siem_targets,
            status="pending",
            queries=queries,
            time_range=time_range,
            hunt_type="sigma",
        )
        self.db.add(hunt)
        await self.db.flush()

        # 4. Run the hunt
        try:
            await self._run_hunt(hunt, mitre_tactics, mitre_techniques)
        except Exception as e:
            hunt.status = "failed"
            hunt.error = str(e)
            await self.db.commit()
            raise

        await self.db.commit()
        await self.db.refresh(hunt)
        return hunt

    async def _run_hunt(self, hunt: Hunt, mitre_tactics: List[str], mitre_techniques: List[str]):
        hunt.status = "running"
        hunt.started_at = datetime.now(timezone.utc)
        await self.db.flush()

        # Load all target SIEM connections
        result = await self.db.execute(
            select(SIEMConnection).where(
                SIEMConnection.id.in_(hunt.siem_targets),
                SIEMConnection.is_active == True,
            )
        )
        connections = result.scalars().all()

        if not connections:
            raise HuntRunnerError("No active SIEM connections found for the given targets")

        # Build tasks
        tasks = []
        conn_map = {}
        for conn in connections:
            try:
                connector = get_connector(conn)
            except ConnectorError as e:
                continue

            query = None
            if connector.siem_type == "elastic" and "elastic" in hunt.queries:
                query = hunt.queries["elastic"]
            elif connector.siem_type == "sentinel" and "sentinel" in hunt.queries:
                query = hunt.queries["sentinel"]

            if not query:
                continue

            tasks.append(connector.run_query(query, max_results=1000))
            conn_map[len(tasks) - 1] = (conn, connector.siem_type)

        if not tasks:
            raise HuntRunnerError("No runnable queries for the available SIEM connections")

        # Run all queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results + persist findings
        total_hits = 0
        errors = []

        for idx, result in enumerate(results):
            conn, siem_type = conn_map[idx]

            if isinstance(result, Exception):
                errors.append(f"{conn.name} ({siem_type}): {result}")
                continue

            if not isinstance(result, list):
                errors.append(f"{conn.name} ({siem_type}): unexpected result type")
                continue

            for raw_event in result:
                ecs_fields = extract_ecs_fields(raw_event)
                finding = HuntResult(
                    hunt_id=hunt.id,
                    siem_connection_id=conn.id,
                    siem_type=siem_type,
                    ecs_event=raw_event,
                    raw_event=raw_event,
                    mitre_techniques=mitre_techniques if mitre_techniques else None,
                    mitre_mapping_source="explicit",
                    **ecs_fields,
                )
                self.db.add(finding)
                total_hits += 1

        hunt.status = "completed"
        hunt.completed_at = datetime.now(timezone.utc)
        hunt.total_hits = total_hits
        if errors:
            hunt.error = "; ".join(errors)

        await self.db.flush()
