"""Findings API — list, inspect, and manage hunt results."""
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user, require_l2_plus
from app.models import FindingSuppression, HuntResult, Incident, SIEMConnection, User
from app.services.corroboration import enrich_findings
from app.services.prioritization import rescore_fingerprint
from app.services.connectors.factory import ConnectorError, get_connector
from app.services.ecs import extract_ecs_fields, get_nested
from app.schemas import (
    ContextEvent, FindingContextResponse, FindingSuppress, SuppressionResult,
    HuntResultResponse, FindingUpdate, FindingEscalate,
    IncidentResponse, PaginatedResponse,
)

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    siem_type: Optional[str] = Query(None, pattern="^(sentinel|elastic|wazuh)$"),
    analyst_status: Optional[str] = Query(None, pattern="^(new|validated|false_positive|escalated)$"),
    source_ip: Optional[str] = Query(None),
    host_name: Optional[str] = Query(None),
    hunt_id: Optional[UUID] = Query(None),
    corroborated: Optional[bool] = Query(None, description="true: only findings that 2+ SIEMs reported"),
    include_suppressed: bool = Query(False, description="also list findings hidden by a suppression"),
    sort: str = Query("priority", pattern="^(priority|time)$", description="priority (default) or newest first"),
    collapse_repeats: bool = Query(True, description="one row per behaviour (latest); false: every hunt's copy"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings with pagination + filtering.

    By default each behaviour appears once: its most recent finding (the same fingerprint found
    again by later hunts is "known", see previous_hunts). Pass collapse_repeats=false for every
    copy. Findings of one specific hunt (hunt_id) are never collapsed. Legacy findings without
    a fingerprint always appear individually.
    """
    conds = []
    if siem_type:
        conds.append(HuntResult.siem_type == siem_type)
    if analyst_status:
        conds.append(HuntResult.analyst_status == analyst_status)
    if source_ip:
        conds.append(HuntResult.source_ip == source_ip)
    if host_name:
        conds.append(HuntResult.host_name == host_name)
    if hunt_id:
        conds.append(HuntResult.hunt_id == hunt_id)
    if not include_suppressed:
        conds.append(HuntResult.suppression_id.is_(None))
    if corroborated is not None:
        conds.append(HuntResult.correlation_id.is_not(None) if corroborated else HuntResult.correlation_id.is_(None))

    if collapse_repeats and not hunt_id:
        latest_per_behaviour = (
            select(HuntResult.id)
            .where(HuntResult.fingerprint.is_not(None), *conds)
            .distinct(HuntResult.fingerprint)
            .order_by(HuntResult.fingerprint, HuntResult.event_time.desc(), HuntResult.created_at.desc())
        )
        conds.append(or_(HuntResult.fingerprint.is_(None), HuntResult.id.in_(latest_per_behaviour)))

    query = select(HuntResult).where(*conds)
    count_query = select(func.count(HuntResult.id)).where(*conds)

    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    order = (
        [HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc()]
        if sort == "priority" else [HuntResult.event_time.desc()]
    )
    result = await db.execute(query.order_by(*order).offset(offset).limit(page_size))
    findings = await enrich_findings(db, result.scalars().all())

    return {
        "items": [HuntResultResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": offset + page_size < total,
    }


@router.get("/{finding_id}", response_model=HuntResultResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single finding with full ECS event + raw event."""
    finding = (await db.execute(
        select(HuntResult).where(HuntResult.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    await enrich_findings(db, [finding])
    return finding


_PIVOT_FIELD = {"host": "host_name", "process": "process_name", "user": "user_name"}


@router.get("/{finding_id}/context", response_model=FindingContextResponse)
async def get_finding_context(
    finding_id: UUID,
    request: Request,
    pivot: str = Query("host", pattern="^(host|process|user)$"),
    window: int = Query(15, ge=1, le=120, description="minutes before and after the finding"),
    limit: int = Query(100, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Events from the finding's own SIEM around the time it was seen (read-only).

    The analyst picks one of three fixed pivots (same host, same process, same user)
    and a bounded window; no query text is accepted. Every call is audited.
    """
    finding = (await db.execute(
        select(HuntResult).where(HuntResult.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    value = getattr(finding, _PIVOT_FIELD[pivot])
    if not value:
        raise HTTPException(status_code=422, detail=f"This finding has no {pivot} to pivot on")

    connection = await db.get(SIEMConnection, finding.siem_connection_id) if finding.siem_connection_id else None
    if connection is None or not connection.is_active:
        raise HTTPException(status_code=409, detail="The SIEM connection for this finding is no longer active")

    try:
        connector = get_connector(connection)
    except ConnectorError as e:
        raise HTTPException(status_code=409, detail=str(e))

    centre = finding.last_seen or finding.event_time
    if centre.tzinfo is None:
        centre = centre.replace(tzinfo=timezone.utc)
    start, end = centre - timedelta(minutes=window), centre + timedelta(minutes=window)
    entity = {"host": finding.host_name, "process_name": finding.process_name, "user": finding.user_name}

    try:
        raw_events = await connector.fetch_context(pivot, entity, start, end, limit)
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"{connection.name}: {e}")

    events = []
    for raw in raw_events:
        fields = extract_ecs_fields(raw)
        events.append(ContextEvent(
            time=fields["event_time"], host=fields["host_name"], user=fields["user_name"],
            process_name=fields["process_name"], pid=get_nested(raw, "process.pid"),
            command_line=fields["process_command_line"], action=fields["action"],
            message=get_nested(raw, "message"), rule_id=get_nested(raw, "rule.id"),
            severity=get_nested(raw, "event.severity"),
        ))

    await log_action(
        db, user_id=current_user.id, action="finding.context",
        target_type="finding", target_id=finding_id,
        metadata={"pivot": pivot, "value": value, "window_minutes": window, "returned": len(events)},
        request=request,
    )
    await db.commit()

    return FindingContextResponse(
        pivot=pivot, entity=entity, siem_type=finding.siem_type, connection_name=connection.name,
        window_minutes=window, time_from=start, time_to=end, count=len(events), events=events,
    )


@router.post("/{finding_id}/suppress", response_model=SuppressionResult)
async def suppress_finding(
    finding_id: UUID,
    payload: FindingSuppress,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_l2_plus),
):
    """Declare a finding's pattern known benign. L2+ only.

    Future hunts flag the same fingerprint as suppressed (hidden by default, never deleted), and
    existing UNREVIEWED findings with that fingerprint are flagged now. Findings an analyst
    validated or escalated are never touched, and such a finding cannot be suppressed.
    """
    finding = (await db.execute(
        select(HuntResult).where(HuntResult.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.fingerprint:
        raise HTTPException(status_code=422, detail="Legacy finding without a fingerprint: re-run the hunt first")
    if finding.analyst_status in ("validated", "escalated"):
        raise HTTPException(status_code=409, detail=f"A {finding.analyst_status} finding cannot be suppressed")

    suppression = (await db.execute(
        select(FindingSuppression).where(FindingSuppression.fingerprint == finding.fingerprint)
    )).scalar_one_or_none()
    if suppression is None:
        suppression = FindingSuppression(fingerprint=finding.fingerprint)
        db.add(suppression)
    suppression.comment = payload.comment
    suppression.created_by = current_user.id
    suppression.is_active = True
    suppression.revoked_by = None
    suppression.revoked_at = None
    await db.flush()

    result = await db.execute(
        update(HuntResult)
        .where(
            HuntResult.fingerprint == finding.fingerprint,
            HuntResult.suppression_id.is_(None),
            HuntResult.analyst_status.in_(("new", "false_positive")),
        )
        .values(suppression_id=suppression.id)
    )
    await rescore_fingerprint(db, finding.fingerprint)
    await log_action(
        db, user_id=current_user.id, action="finding.suppress",
        target_type="finding", target_id=finding_id,
        metadata={"fingerprint": finding.fingerprint, "comment": payload.comment, "affected": result.rowcount},
        request=request,
    )
    await db.commit()
    return SuppressionResult(suppression_id=suppression.id, affected=result.rowcount)


@router.delete("/{finding_id}/suppress", response_model=SuppressionResult)
async def unsuppress_finding(
    finding_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_l2_plus),
):
    """Revoke the suppression covering this finding; everything it hid becomes visible again."""
    finding = (await db.execute(
        select(HuntResult).where(HuntResult.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    suppression = (await db.execute(
        select(FindingSuppression).where(
            FindingSuppression.fingerprint == finding.fingerprint,
            FindingSuppression.is_active.is_(True),
        )
    )).scalar_one_or_none() if finding.fingerprint else None
    if suppression is None:
        raise HTTPException(status_code=404, detail="This finding is not suppressed")

    suppression.is_active = False
    suppression.revoked_by = current_user.id
    suppression.revoked_at = datetime.now(timezone.utc)
    result = await db.execute(
        update(HuntResult).where(HuntResult.suppression_id == suppression.id).values(suppression_id=None)
    )
    await rescore_fingerprint(db, finding.fingerprint)
    await log_action(
        db, user_id=current_user.id, action="finding.unsuppress",
        target_type="finding", target_id=finding_id,
        metadata={"fingerprint": finding.fingerprint, "affected": result.rowcount},
        request=request,
    )
    await db.commit()
    return SuppressionResult(suppression_id=suppression.id, affected=result.rowcount)


@router.patch("/{finding_id}", response_model=HuntResultResponse)
async def update_finding(
    finding_id: UUID,
    update: FindingUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_l2_plus),
):
    """Update analyst workflow status + comment on a finding. L2+ only."""
    finding = (await db.execute(
        select(HuntResult).where(HuntResult.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    changes = {}
    if update.analyst_status is not None and update.analyst_status != finding.analyst_status:
        finding.analyst_status = update.analyst_status
        changes["analyst_status"] = update.analyst_status
    if update.analyst_comment is not None:
        finding.analyst_comment = update.analyst_comment
        changes["analyst_comment"] = update.analyst_comment

    if changes:
        finding.reviewed_by = current_user.id
        finding.reviewed_at = datetime.utcnow()

        await rescore_fingerprint(db, finding.fingerprint)      # a decision changes every copy's priority
        await log_action(
            db, user_id=current_user.id, action="finding.update",
            target_type="finding", target_id=finding_id,
            metadata=changes, request=request,
        )
        await db.commit()
        await db.refresh(finding)

    await enrich_findings(db, [finding])
    return finding


@router.post("/{finding_id}/escalate", response_model=IncidentResponse)
async def escalate_finding(
    finding_id: UUID,
    escalate: FindingEscalate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_l2_plus),
):
    """Escalate a finding to an incident. L2+ only."""
    finding = (await db.execute(
        select(HuntResult).where(HuntResult.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if escalate.incident_id:
        incident = (await db.execute(
            select(Incident).where(Incident.id == escalate.incident_id)
        )).scalar_one_or_none()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
    else:
        if not escalate.new_incident_title:
            raise HTTPException(
                status_code=422,
                detail="new_incident_title required when incident_id is not provided"
            )
        incident = Incident(
            title=escalate.new_incident_title,
            severity=escalate.new_incident_severity or "medium",
            mitre_techniques=finding.mitre_techniques,
            created_by=current_user.id,
        )
        db.add(incident)
        await db.flush()

    finding.incident_id = incident.id
    finding.analyst_status = "escalated"
    finding.reviewed_by = current_user.id
    finding.reviewed_at = datetime.utcnow()

    await rescore_fingerprint(db, finding.fingerprint)
    await log_action(
        db, user_id=current_user.id, action="finding.escalate",
        target_type="finding", target_id=finding_id,
        metadata={
            "incident_id": str(incident.id),
            "incident_title": incident.title,
        },
        request=request,
    )
    await db.commit()
    await db.refresh(incident)

    return incident
