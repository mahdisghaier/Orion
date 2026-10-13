"""Pydantic v2 schemas — API request/response models.

Separate from SQLAlchemy models: these define what the API accepts/returns.
SQLAlchemy models define what's stored in the database.
"""
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ─────────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access_token expires


class TokenData(BaseModel):
    user_id: Optional[UUID] = None
    role: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ─────────────────────────────────────────────────────────────────
# USER
# ─────────────────────────────────────────────────────────────────
class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=200)
    role: str = Field(..., pattern="^(admin|soc_l1|soc_l2|soc_l3)$")


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=200)
    role: Optional[str] = Field(None, pattern="^(admin|soc_l1|soc_l2|soc_l3)$")
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    is_active: bool
    created_at: datetime


# ─────────────────────────────────────────────────────────────────
# SIEM CONNECTION
# ─────────────────────────────────────────────────────────────────
class SIEMConnectionBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., pattern="^(sentinel|elastic|wazuh)$")


class SIEMConnectionCreate(SIEMConnectionBase):
    # Config is flexible JSON — different per SIEM type
    # Sentinel: {tenant_id, client_id, client_secret, workspace_id}
    # Elastic:  {url, api_key, index_pattern}
    config: dict


class SIEMConnectionResponse(SIEMConnectionBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    is_active: bool
    created_at: datetime
    # Never return the encrypted config — only metadata
    # Admin gets connection list, then fetches config separately if needed


class SIEMConnectionTestResult(BaseModel):
    success: bool
    message: str
    latency_ms: Optional[int] = None


# ─────────────────────────────────────────────────────────────────
# SIGMA RULE
# ─────────────────────────────────────────────────────────────────
class SigmaRuleBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    yaml: str
    source: str = Field(default="custom", pattern="^(community|custom)$")
    rule_uuid: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    author: Optional[str] = None


class SigmaRuleCreate(SigmaRuleBase):
    parent_rule_id: Optional[UUID] = None


class SigmaRuleUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    yaml: Optional[str] = None
    lifecycle_status: Optional[str] = Field(
        None, pattern="^(draft|testing|active|deprecated|retired)$"
    )


class SigmaRuleResponse(SigmaRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    parent_rule_id: Optional[UUID] = None
    lifecycle_status: str
    false_positive_count: int
    true_positive_count: int
    last_evaluated_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


# ─────────────────────────────────────────────────────────────────
# HUNT
# ─────────────────────────────────────────────────────────────────
class HuntCreate(BaseModel):
    """Request to create + run a hunt.

    Provide EITHER rule_id (existing Sigma rule from library)
    OR rule_yaml (inline Sigma YAML). The backend converts to
    KQL + EQL automatically — no need to send queries manually.
    """
    rule_id: Optional[UUID] = None
    rule_yaml: Optional[str] = None
    siem_targets: List[UUID] = Field(..., min_length=1)
    time_range: Optional[dict] = None  # {"from": "...", "to": "..."}
    hunt_type: str = Field(default="sigma", pattern="^(sigma|kestrel)$")


class HuntResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: Optional[UUID] = None
    created_by: UUID
    siem_targets: List[UUID]
    status: str
    queries: dict
    time_range: Optional[dict] = None
    hunt_type: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_hits: int
    error: Optional[str] = None
    created_at: datetime


# ─────────────────────────────────────────────────────────────────
# HUNT RESULT / FINDING
# ─────────────────────────────────────────────────────────────────
class HuntResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    hunt_id: UUID
    siem_type: str
    event_time: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    process_name: Optional[str] = None
    process_command_line: Optional[str] = None
    action: Optional[str] = None
    ecs_event: dict
    mitre_techniques: Optional[List[str]] = None
    mitre_mapping_source: str
    analyst_status: str
    analyst_comment: Optional[str] = None
    reviewed_by: Optional[UUID] = None
    reviewed_at: Optional[datetime] = None
    incident_id: Optional[UUID] = None
    created_at: datetime


class FindingUpdate(BaseModel):
    """Analyst workflow — update finding status/comment."""
    analyst_status: Optional[str] = Field(
        None, pattern="^(new|validated|false_positive|escalated)$"
    )
    analyst_comment: Optional[str] = None


class FindingEscalate(BaseModel):
    """Escalate finding to a new or existing incident."""
    incident_id: Optional[UUID] = None  # if None, create new incident
    new_incident_title: Optional[str] = None
    new_incident_severity: Optional[str] = Field(
        None, pattern="^(low|medium|high|critical)$"
    )


# ─────────────────────────────────────────────────────────────────
# INCIDENT
# ─────────────────────────────────────────────────────────────────
class IncidentBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None


class IncidentCreate(IncidentBase):
    assigned_to: Optional[UUID] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    status: Optional[str] = Field(
        None, pattern="^(open|investigating|contained|closed)$"
    )
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    assigned_to: Optional[UUID] = None


class IncidentResponse(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    created_by: UUID
    assigned_to: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime


# ─────────────────────────────────────────────────────────────────
# ANALYST FEEDBACK
# ─────────────────────────────────────────────────────────────────
class AnalystFeedbackCreate(BaseModel):
    label: str = Field(..., pattern="^(true_positive|false_positive|uncertain)$")
    comment: Optional[str] = None


class AnalystFeedbackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    user_id: UUID
    label: str
    llm_confidence_at_time: Optional[float] = None
    comment: Optional[str] = None
    created_at: datetime


# ─────────────────────────────────────────────────────────────────
# PAGINATION
# ─────────────────────────────────────────────────────────────────
class PaginatedResponse(BaseModel):
    """Generic paginated response wrapper."""
    items: List
    total: int
    page: int
    page_size: int
    has_next: bool

# ─────────────────────────────────────────────────────────────────
# SIGMA CONVERSION
# ─────────────────────────────────────────────────────────────────
class SigmaConvertRequest(BaseModel):
    rule_yaml: str = Field(..., min_length=1)


class SigmaConvertResponse(BaseModel):
    kql: Optional[str] = None
    kql_error: Optional[str] = None
    eql: Optional[str] = None
    eql_error: Optional[str] = None