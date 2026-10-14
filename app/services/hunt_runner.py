"""Hunt Runner — Layer 3/6. Orchestrates the full hunt flow."""
import asyncio
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID
import yaml

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import FindingSuppression, Hunt, HuntResult, SIEMConnection, SigmaRule
from app.services.connectors.factory import get_connector, ConnectorError
from app.services.ecs import extract_ecs_fields, extract_mitre_from_tags
from app.services.correlation import Candidate, correlate
from app.services.grouping import group_events
from app.services.prioritization import rescore_findings
from app.services.sigma_engine import convert_sigma_rule, unmapped_fields


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
                parsed, tags, mitre_tactics, mitre_techniques = None, [], [], []
            rule_id = await self._save_inline_rule(rule_yaml, parsed, tags, mitre_tactics, mitre_techniques)
        else:
            raise HuntRunnerError("Either rule_id or rule_yaml must be provided")

        # 2. Convert Sigma → KQL + EQL
        conversion = convert_sigma_rule(rule_yaml)
        queries = {}
        if conversion.get("kql"):
            queries["sentinel"] = conversion["kql"]
        if conversion.get("eql"):
            queries["elastic"] = conversion["eql"]
        if conversion.get("lucene"):
            queries["wazuh"] = conversion["lucene"]

        if not queries:
            errors = []
            if conversion.get("kql_error"):
                errors.append(f"KQL: {conversion['kql_error']}")
            if conversion.get("eql_error"):
                errors.append(f"EQL: {conversion['eql_error']}")
            if conversion.get("lucene_error"):
                errors.append(f"Lucene: {conversion['lucene_error']}")
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
            await self._run_hunt(hunt, rule_yaml, mitre_tactics, mitre_techniques)
        except Exception as e:
            hunt.status = "failed"
            hunt.error = str(e)
            await self.db.commit()
            raise

        await self.db.commit()
        await self.db.refresh(hunt)
        return hunt

    async def _save_inline_rule(self, rule_yaml, parsed, tags, mitre_tactics, mitre_techniques) -> Optional[UUID]:
        """Keep the exact rule a hunt ran, so every finding can be traced back to it.

        A rule is stored once per distinct YAML text (an edited rule is a new row, old hunts
        keep pointing at what they actually ran). Returns None when the YAML is not a mapping.
        """
        if not isinstance(parsed, dict):
            return None
        existing = (await self.db.execute(
            select(SigmaRule).where(SigmaRule.yaml == rule_yaml).limit(1)
        )).scalar_one_or_none()
        if existing:
            return existing.id

        rule_uuid = str(parsed["id"]) if parsed.get("id") else None
        if rule_uuid and (await self.db.execute(
            select(SigmaRule.id).where(SigmaRule.rule_uuid == rule_uuid)
        )).first():
            rule_uuid = None            # that UUID belongs to an earlier version of the rule

        rule = SigmaRule(
            title=str(parsed.get("title") or "Untitled hunt rule")[:500],
            rule_uuid=rule_uuid,
            yaml=rule_yaml,
            source="custom",
            mitre_tactics=mitre_tactics or None,
            mitre_techniques=mitre_techniques or None,
            tags=[str(t) for t in tags] or None,
            author=str(parsed["author"]) if parsed.get("author") else None,
        )
        self.db.add(rule)
        await self.db.flush()
        return rule.id

    async def _run_hunt(self, hunt: Hunt, rule_yaml: str, mitre_tactics: List[str], mitre_techniques: List[str]):
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

        # Build tasks. Anything that prevents a SIEM from being queried is recorded in
        # `notes`, never dropped silently: "0 hits" must not hide "could not look".
        tasks = []
        conn_map = {}
        notes = []
        for conn in connections:
            try:
                connector = get_connector(conn)
            except ConnectorError as e:
                notes.append(f"{conn.name} ({conn.type}): {e}")
                continue

            query = hunt.queries.get(connector.siem_type)
            if not query:
                notes.append(f"{conn.name} ({connector.siem_type}): no query could be generated for this SIEM")
                continue

            missing = unmapped_fields(rule_yaml, connector.siem_type)
            if missing:
                notes.append(
                    f"{conn.name} ({connector.siem_type}): not runnable, no field for "
                    f"{', '.join(missing)} in this SIEM's data"
                )
                continue

            tasks.append(connector.run_query(query, max_results=1000, time_range=hunt.time_range))
            conn_map[len(tasks) - 1] = (conn, connector.siem_type)

        if not tasks:
            raise HuntRunnerError(
                "No runnable queries for the selected SIEM connections: " + "; ".join(notes)
                if notes else "No runnable queries for the selected SIEM connections"
            )

        # Run all queries in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results + persist findings
        total_hits = 0
        errors = list(notes)
        failed_queries = 0
        findings: List[HuntResult] = []

        for idx, result in enumerate(results):
            conn, siem_type = conn_map[idx]

            if isinstance(result, Exception):
                errors.append(f"{conn.name} ({siem_type}): {result}")
                failed_queries += 1
                continue

            if not isinstance(result, list):
                errors.append(f"{conn.name} ({siem_type}): unexpected result type")
                failed_queries += 1
                continue

            # Repeated samples of one behaviour become ONE finding with a count (grouping.py)
            items = [(event, extract_ecs_fields(event)) for event in result]
            for group in group_events(siem_type, items):
                finding = HuntResult(
                    hunt_id=hunt.id,
                    siem_connection_id=conn.id,
                    siem_type=siem_type,
                    ecs_event=group.event,
                    raw_event=group.event,
                    fingerprint=group.fingerprint,
                    occurrence_count=group.count,
                    first_seen=group.first_seen,
                    last_seen=group.last_seen,
                    mitre_techniques=mitre_techniques if mitre_techniques else None,
                    mitre_mapping_source="explicit",
                    **group.fields,
                )
                self.db.add(finding)
                findings.append(finding)
                total_hits += 1

        # Same behaviour reported by different SIEMs -> shared correlation_id
        ids = correlate([
            Candidate(f.siem_type, f.host_name, f.process_name, f.first_seen, f.last_seen) for f in findings
        ])
        for finding, correlation_id in zip(findings, ids):
            finding.correlation_id = correlation_id

        # Behaviour an analyst already declared benign stays flagged, so it is not triaged again
        fingerprints = {f.fingerprint for f in findings}
        if fingerprints:
            rows = (await self.db.execute(
                select(FindingSuppression.id, FindingSuppression.fingerprint).where(
                    FindingSuppression.fingerprint.in_(fingerprints),
                    FindingSuppression.is_active.is_(True),
                )
            )).all()
            suppressed = {fp: sid for sid, fp in rows}
            for finding in findings:
                finding.suppression_id = suppressed.get(finding.fingerprint)

        # Priority needs the findings, correlation and suppression above; hunt.rule_id is already set
        await self.db.flush()
        await rescore_findings(self.db, findings)

        # Every SIEM that was queried failed: this is a failed hunt, not a clean one.
        hunt.status = "failed" if failed_queries == len(tasks) else "completed"
        hunt.completed_at = datetime.now(timezone.utc)
        hunt.total_hits = total_hits
        if errors:
            hunt.error = "; ".join(errors)

        await self.db.flush()
