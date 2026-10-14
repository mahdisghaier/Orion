"""Investigations (hunt records) — the human-in-the-loop hunting workflow.

An analyst states a hypothesis. ORION proposes next steps (a Sigma rule to hunt, or a pivot on a
finding); the analyst approves or rejects each one; ONLY approved steps run; every outcome is kept.
The concluded record (hypothesis, steps, who approved what, results, verdict) is the source for
reports and notebooks.

- POST /api/investigations/                      create (optionally from a finding)
- GET  /api/investigations/                      list
- GET  /api/investigations/{id}                  one, with its steps
- POST /api/investigations/{id}/propose          propose next steps (AI + rule-based, validated)
- POST /api/investigations/{id}/steps                 add your own rule step (validated like an AI proposal)
- POST /api/investigations/{id}/steps/{sid}/approve   approve AND run a proposed step
- POST /api/investigations/{id}/steps/{sid}/reject    reject a proposed step
- POST /api/investigations/{id}/conclude         verdict + conclusion (L2+)
"""
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user, require_l2_plus
from app.models import (
    HuntResult, Investigation, InvestigationStep, LLMAudit, SIEMConnection, SIEMProfile, User,
)
from app.schemas import (
    InvestigationConclude, InvestigationCreate, InvestigationResponse, InvestigationStepResponse,
    ProposeResponse, StepCreate, StepDecision,
)
from app.services.investigation.context import build_context
from app.services.investigation.executor import execute_step
from app.services.investigation.proposer import assess_rule, propose_steps, step_signature

router = APIRouter()


async def _load(db: AsyncSession, investigation_id: UUID) -> Investigation:
    inv = (await db.execute(
        select(Investigation).options(selectinload(Investigation.steps)).where(Investigation.id == investigation_id)
    )).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


def _require_open(inv: Investigation) -> None:
    if inv.status != "open":
        raise HTTPException(status_code=409, detail="This investigation is concluded")


@router.post("/", response_model=InvestigationResponse, status_code=201)
async def create_investigation(
    payload: InvestigationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    title, hypothesis = payload.title, payload.hypothesis
    if payload.from_finding_id:
        finding = await db.get(HuntResult, payload.from_finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")

    targets = payload.siem_targets
    if not targets:
        targets = [c.id for c in (await db.execute(
            select(SIEMConnection).where(SIEMConnection.is_active.is_(True))
        )).scalars().all()]
    if not targets:
        raise HTTPException(status_code=422, detail="No active SIEM connections to investigate with")

    inv = Investigation(
        title=title, hypothesis=hypothesis, siem_targets=targets, time_range=payload.time_range,
        source_finding_id=payload.from_finding_id, created_by=current_user.id,
    )
    db.add(inv)
    await db.flush()
    await log_action(
        db, user_id=current_user.id, action="investigation.create", target_type="investigation", target_id=inv.id,
        metadata={"title": title[:200], "from_finding": str(payload.from_finding_id) if payload.from_finding_id else None},
        request=request,
    )
    await db.commit()
    return await _load(db, inv.id)


@router.get("/", response_model=list[InvestigationResponse])
async def list_investigations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (await db.execute(
        select(Investigation).options(selectinload(Investigation.steps)).order_by(Investigation.created_at.desc()).limit(100)
    )).scalars().all()
    return rows


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _load(db, investigation_id)


@router.post("/{investigation_id}/propose", response_model=ProposeResponse)
async def propose(
    investigation_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Propose the next steps. Proposals are stored as 'proposed'; nothing runs until an analyst approves."""
    inv = await _load(db, investigation_id)
    _require_open(inv)

    context = await build_context(db, inv)
    targets = await _siem_targets(db, inv)
    existing = {step_signature(s.kind, s.payload) for s in inv.steps}

    proposal = await propose_steps(context, inv.hypothesis, targets, existing)

    # Full audit trail of every model call (prompt, the facts it was given, raw reply, what validation did)
    for audit in proposal.audits:
        db.add(LLMAudit(
            user_id=current_user.id,
            chat_session_id=inv.id,
            prompt=audit["prompt"][:20000],
            retrieved_context={"context": audit.get("context"), "facts_given": context},
            raw_response=audit["response"][:20000],
            parsed_response=audit.get("parsed") or {"unusable": True},
            model=audit["model"],
            provider=audit["provider"],
            latency_ms=audit.get("latency_ms"),
            was_rejected=bool(audit.get("rejection")),
            rejection_reason=audit.get("rejection"),
        ))

    next_seq = (max((s.seq for s in inv.steps), default=0)) + 1
    new_steps = []
    for item in proposal.steps:
        step = InvestigationStep(investigation_id=inv.id, seq=next_seq, status="proposed", **item)
        db.add(step)
        new_steps.append(step)
        next_seq += 1

    await log_action(
        db, user_id=current_user.id, action="investigation.propose", target_type="investigation", target_id=inv.id,
        metadata={"proposed": len(new_steps), "rejected": len(proposal.rejected),
                  "ai_used": any(s.proposed_by == "ai" for s in new_steps)},
        request=request,
    )
    await db.commit()
    for step in new_steps:
        await db.refresh(step)
    return ProposeResponse(
        new_steps=[InvestigationStepResponse.model_validate(s) for s in new_steps],
        rejected=proposal.rejected, notes=proposal.notes,
    )


async def _siem_targets(db: AsyncSession, inv: Investigation) -> list:
    connections = (await db.execute(
        select(SIEMConnection).where(SIEMConnection.id.in_(inv.siem_targets), SIEMConnection.is_active.is_(True))
    )).scalars().all()
    profiles = {
        r.siem_connection_id: r.profile
        for r in (await db.execute(
            select(SIEMProfile).where(SIEMProfile.siem_connection_id.in_([c.id for c in connections]))
        )).scalars().all()
    }
    return [{"conn_id": str(c.id), "name": c.name, "siem_type": c.type, "profile": profiles.get(c.id)}
            for c in connections]


@router.post("/{investigation_id}/steps", response_model=InvestigationStepResponse, status_code=201)
async def add_step(
    investigation_id: UUID,
    payload: StepCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The analyst adds a Sigma rule step. Same validation as an AI proposal; it still waits for approval."""
    inv = await _load(db, investigation_id)
    _require_open(inv)
    assessment, reason = assess_rule(payload.sigma_rule, await _siem_targets(db, inv))
    if reason:
        raise HTTPException(status_code=422, detail=reason)
    rule_payload = {"sigma_rule": payload.sigma_rule.strip(), "cites": []}
    if step_signature("rule", rule_payload) in {step_signature(s.kind, s.payload) for s in inv.steps}:
        raise HTTPException(status_code=409, detail="This rule is already a step of the investigation")

    step = InvestigationStep(
        investigation_id=inv.id, seq=max((s.seq for s in inv.steps), default=0) + 1, kind="rule",
        title=payload.title, rationale=payload.rationale or "Analyst-authored step", proposed_by="analyst",
        payload=rule_payload, assessment=assessment, status="proposed",
    )
    db.add(step)
    await log_action(
        db, user_id=current_user.id, action="investigation.step.add", target_type="investigation",
        target_id=inv.id, metadata={"title": payload.title[:120]}, request=request,
    )
    await db.commit()
    await db.refresh(step)
    return step


async def _step_of(inv: Investigation, step_id: UUID) -> InvestigationStep:
    step = next((s for s in inv.steps if s.id == step_id), None)
    if step is None:
        raise HTTPException(status_code=404, detail="Step not found in this investigation")
    if step.status != "proposed":
        raise HTTPException(status_code=409, detail=f"This step is already {step.status}")
    return step


@router.post("/{investigation_id}/steps/{step_id}/approve", response_model=InvestigationStepResponse)
async def approve_step(
    investigation_id: UUID,
    step_id: UUID,
    request: Request,
    decision: StepDecision = StepDecision(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The analyst authorises this step; it runs now and its outcome is recorded."""
    inv = await _load(db, investigation_id)
    _require_open(inv)
    step = await _step_of(inv, step_id)

    step.status = "approved"
    step.decided_by = current_user.id
    step.decided_at = datetime.now(timezone.utc)
    step.decision_comment = decision.comment
    await db.flush()

    await execute_step(db, inv, step, current_user)

    await log_action(
        db, user_id=current_user.id, action="investigation.step.approve", target_type="investigation",
        target_id=inv.id,
        metadata={"step": step.seq, "kind": step.kind, "outcome": step.status,
                  "hunt_id": str(step.hunt_id) if step.hunt_id else None},
        request=request,
    )
    await db.commit()
    await db.refresh(step)
    return step


@router.post("/{investigation_id}/steps/{step_id}/reject", response_model=InvestigationStepResponse)
async def reject_step(
    investigation_id: UUID,
    step_id: UUID,
    request: Request,
    decision: StepDecision = StepDecision(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    inv = await _load(db, investigation_id)
    _require_open(inv)
    step = await _step_of(inv, step_id)
    step.status = "rejected"
    step.decided_by = current_user.id
    step.decided_at = datetime.now(timezone.utc)
    step.decision_comment = decision.comment
    await log_action(
        db, user_id=current_user.id, action="investigation.step.reject", target_type="investigation",
        target_id=inv.id, metadata={"step": step.seq, "kind": step.kind, "comment": decision.comment},
        request=request,
    )
    await db.commit()
    await db.refresh(step)
    return step


@router.post("/{investigation_id}/conclude", response_model=InvestigationResponse)
async def conclude(
    investigation_id: UUID,
    payload: InvestigationConclude,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_l2_plus),
):
    """Close the investigation with a verdict. L2+ only. Steps still waiting for a decision are kept as proposed."""
    inv = await _load(db, investigation_id)
    _require_open(inv)
    inv.status = "concluded"
    inv.verdict = payload.verdict
    inv.conclusion = payload.conclusion
    inv.concluded_by = current_user.id
    inv.concluded_at = datetime.now(timezone.utc)
    await log_action(
        db, user_id=current_user.id, action="investigation.conclude", target_type="investigation",
        target_id=inv.id, metadata={"verdict": payload.verdict}, request=request,
    )
    await db.commit()
    return await _load(db, inv.id)
