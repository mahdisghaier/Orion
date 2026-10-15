"""Hunt coverage: which technique rules can run on which connected SIEM, and why not.

- GET /api/coverage            the matrix (technique x SIEM)
- GET /api/coverage/navigator  the same as an ATT&CK Navigator layer (JSON file)
"""
import json

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import User
from app.services.threat_intel.coverage import active_connections_with_profiles, matrix, navigator_layer

router = APIRouter()


@router.get("/")
async def get_coverage(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return matrix(await active_connections_with_profiles(db))


@router.get("/navigator")
async def get_navigator_layer(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    layer = navigator_layer(matrix(await active_connections_with_profiles(db)))
    return Response(json.dumps(layer, indent=1), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="orion-coverage-layer.json"'})
