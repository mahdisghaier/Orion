"""Run an APPROVED investigation step and record what came out."""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HuntResult, Investigation, InvestigationStep, User
from app.services.finding_context import ContextError, fetch_finding_context
from app.services.hunt_runner import HuntRunner, HuntRunnerError

MAX_STORED_EVENTS = 100


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


# [explain] Runs ONE approved step. A rule step hunts the rule; a pivot step looks around a finding.
# [explain] Whatever happens (success, error) is written on the step, so the record is complete.
async def execute_step(db: AsyncSession, inv: Investigation, step: InvestigationStep, user: User) -> None:
    """Executes the step and sets its result / status. The caller commits."""
    step.executed_at = datetime.now(timezone.utc)
    try:
        if step.kind == "rule":
            hunt = await HuntRunner(db).create_and_run(
                created_by=user.id,
                siem_targets=list(inv.siem_targets),
                rule_yaml=step.payload["sigma_rule"],
                time_range=inv.time_range,
            )
            top = (await db.execute(
                select(HuntResult).where(HuntResult.hunt_id == hunt.id)
                .order_by(HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc()).limit(20)
            )).scalars().all()
            step.hunt_id = hunt.id
            step.result = {
                "hunt_id": str(hunt.id),
                "hunt_status": hunt.status,
                "total_hits": hunt.total_hits,
                "notes": hunt.error,
                "findings": [{"id": str(f.id), "siem_type": f.siem_type, "process_name": f.process_name,
                              "host_name": f.host_name, "priority_score": f.priority_score,
                              "occurrences": f.occurrence_count} for f in top],
            }
            if hunt.status == "completed":
                step.status = "executed"
            else:
                step.status, step.error = "failed", hunt.error or "the hunt failed"
        else:
            payload = step.payload
            finding = await db.get(HuntResult, payload["finding_id"])
            if finding is None:
                raise ContextError(404, "The finding this step refers to no longer exists")
            ctx = await fetch_finding_context(db, finding, payload["pivot"], payload["window_minutes"], MAX_STORED_EVENTS)
            step.result = {
                "pivot": ctx["pivot"], "entity": ctx["entity"], "siem_type": ctx["siem_type"],
                "connection_name": ctx["connection_name"], "window_minutes": ctx["window_minutes"],
                "time_from": _iso(ctx["time_from"]), "time_to": _iso(ctx["time_to"]),
                "count": len(ctx["events"]),
                "events": [{k: _iso(v) for k, v in e.items()} for e in ctx["events"]],
            }
            step.status = "executed"
    except (HuntRunnerError, ContextError) as e:
        step.status, step.error = "failed", getattr(e, "detail", None) or str(e)
    except Exception as e:                                    # never leave a step half-run
        step.status, step.error = "failed", f"{type(e).__name__}: {e}"
