"""Sigma rule conversion — preview KQL/EQL output without running a hunt.

- POST /api/sigma/convert — convert a Sigma rule to KQL + EQL
"""
from fastapi import APIRouter, Depends

from app.core.deps import require_l2_plus
from app.models import User
from app.schemas import SigmaConvertRequest, SigmaConvertResponse
from app.services.sigma_engine import convert_sigma_rule

router = APIRouter()


# [explain] Preview only: turns a Sigma rule into the query languages without searching anything.
# [explain] Handy to see why a rule behaves strangely before running it for real.
@router.post("/convert", response_model=SigmaConvertResponse)
async def convert_rule(
    payload: SigmaConvertRequest,
    current_user: User = Depends(require_l2_plus),
):
    """Convert a Sigma rule to KQL and EQL, independent of any live hunt.

    Useful for previewing conversion output before running an actual
    hunt, or debugging why a rule doesn't behave as expected against
    a specific SIEM.
    """
    result = convert_sigma_rule(payload.rule_yaml)
    return SigmaConvertResponse(**result)