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
# CLIENT
# ─────────────────────────────────────────────────────────────────
class ClientCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class ClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    is_active: bool
    created_at: datetime


# ─────────────────────────────────────────────────────────────────
# USER
# ─────────────────────────────────────────────────────────────────
class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=200)
    role: str = Field(..., pattern="^(admin|soc_l1|soc_l2|soc_l3)$")


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    client_id: Optional[UUID] = None      # none: a platform-wide user (the SOC's own staff)


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=200)
    role: Optional[str] = Field(None, pattern="^(admin|soc_l1|soc_l2|soc_l3)$")
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    client_id: Optional[UUID] = None
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
    # Wazuh:    {url, username, password, verify_ssl, index_pattern, host_aliases}
    config: dict
    client_id: Optional[UUID] = None      # default: the caller's client


class SIEMConnectionResponse(SIEMConnectionBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    client_id: Optional[UUID] = None
    is_active: bool
    created_at: datetime
    # Never return the encrypted config — only metadata
    # Admin gets connection list, then fetches config separately if needed


class SIEMProfileResponse(BaseModel):
    """What a SIEM connection can actually see (see services/data_profile.py)."""
    model_config = ConfigDict(from_attributes=True)

    siem_connection_id: UUID
    profile: dict
    collected_at: datetime


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
    client_id: Optional[UUID] = None     # default: the client of the targeted connections


class HuntResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    client_id: Optional[UUID] = None
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
class CorroboratingFinding(BaseModel):
    """Another finding of the same hunt that a different SIEM reported for the same behaviour."""
    id: UUID
    siem_type: str


class HuntResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    client_id: Optional[UUID] = None
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
    occurrence_count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    correlation_id: Optional[str] = None
    corroborated_by: List[CorroboratingFinding] = []
    suppression_id: Optional[UUID] = None
    suppressed: bool = False
    priority_score: Optional[int] = None
    priority_breakdown: Optional[List[dict]] = None
    previous_hunts: int = 0
    known_since: Optional[datetime] = None
    ecs_event: dict
    mitre_techniques: Optional[List[str]] = None
    mitre_mapping_source: str
    analyst_status: str
    analyst_comment: Optional[str] = None
    reviewed_by: Optional[UUID] = None
    reviewed_at: Optional[datetime] = None
    incident_id: Optional[UUID] = None
    created_at: datetime


class ContextEvent(BaseModel):
    """One event around a finding, reduced to what an analyst scans."""
    time: Optional[datetime] = None
    host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None
    action: Optional[str] = None
    message: Optional[str] = None
    rule_id: Optional[str] = None
    severity: Optional[int] = None


class FindingContextResponse(BaseModel):
    """Read-only events from the finding's own SIEM around the time it was seen."""
    pivot: str
    entity: dict
    siem_type: str
    connection_name: str
    window_minutes: int
    time_from: datetime
    time_to: datetime
    count: int
    events: List[ContextEvent]


class FindingSuppress(BaseModel):
    """Suppress a finding's pattern: it is known benign and should be hidden in future hunts."""
    comment: Optional[str] = Field(None, max_length=1000)


class SuppressionResult(BaseModel):
    suppression_id: UUID
    affected: int          # findings hidden (suppress) or restored (unsuppress)


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
# INVESTIGATION (hunt record)
# ─────────────────────────────────────────────────────────────────
class InvestigationCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    hypothesis: str = Field(..., min_length=1, max_length=2000)
    siem_targets: Optional[List[UUID]] = None     # default: every active SIEM connection
    time_range: Optional[dict] = None
    from_finding_id: Optional[UUID] = None
    client_id: Optional[UUID] = None


class StepCreate(BaseModel):
    """An analyst-authored rule step. It is validated like an AI proposal and still needs approval."""
    title: str = Field(..., min_length=1, max_length=120)
    rationale: Optional[str] = Field(None, max_length=600)
    sigma_rule: str = Field(..., min_length=1, max_length=20000)


class StepDecision(BaseModel):
    comment: Optional[str] = Field(None, max_length=1000)


class InvestigationConclude(BaseModel):
    verdict: str = Field(..., pattern="^(true_positive|false_positive|inconclusive)$")
    conclusion: str = Field(..., min_length=1, max_length=4000)


class InvestigationStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    investigation_id: UUID
    seq: int
    kind: str
    title: str
    rationale: str
    proposed_by: str
    payload: dict
    assessment: Optional[dict] = None
    status: str
    decided_by: Optional[UUID] = None
    decided_at: Optional[datetime] = None
    decision_comment: Optional[str] = None
    hunt_id: Optional[UUID] = None
    result: Optional[dict] = None
    error: Optional[str] = None
    executed_at: Optional[datetime] = None
    created_at: datetime


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    client_id: Optional[UUID] = None
    title: str
    hypothesis: str
    status: str
    verdict: Optional[str] = None
    conclusion: Optional[str] = None
    siem_targets: List[UUID]
    time_range: Optional[dict] = None
    source_finding_id: Optional[UUID] = None
    created_by: UUID
    concluded_by: Optional[UUID] = None
    created_at: datetime
    concluded_at: Optional[datetime] = None
    steps: List[InvestigationStepResponse] = []


class ProposeResponse(BaseModel):
    new_steps: List[InvestigationStepResponse]
    rejected: List[dict]          # AI proposals that validation refused, with the reason
    notes: List[str]


# ─────────────────────────────────────────────────────────────────
# SCHEDULED JOBS + NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────
class JobConfig(BaseModel):
    """Settings of a threat-intelligence job. Unknown keys are refused rather than silently ignored."""
    model_config = ConfigDict(extra="forbid")

    campaigns: int = Field(8, ge=1, le=30, description="how many of the most recent ATT&CK campaigns to take techniques from")
    max_techniques: int = Field(30, ge=1, le=60)
    platform: str = Field("Linux", pattern="^(Linux|Windows|macOS)$")
    kev_days: int = Field(7, ge=1, le=30, description="how far back the first run looks")
    custom_iocs: dict = Field(default_factory=dict, description='{"ip": [...], "domain": [...], "sha256": [...]}')


class JobCreate(BaseModel):
    name: str = Field("Daily threat-intelligence check", min_length=1, max_length=120)
    kind: str = Field("threat_intel", pattern="^threat_intel$")
    interval_hours: int = Field(24, ge=1, le=336)
    enabled: bool = True
    config: JobConfig = Field(default_factory=JobConfig)
    client_id: Optional[UUID] = None


class JobUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    interval_hours: Optional[int] = Field(None, ge=1, le=336)
    enabled: Optional[bool] = None
    config: Optional[JobConfig] = None


class JobRunBrief(BaseModel):
    id: UUID
    status: str
    trigger: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    headline: Optional[str] = None
    error: Optional[str] = None


class JobResponse(BaseModel):
    id: UUID
    client_id: Optional[UUID] = None
    name: str
    kind: str
    interval_hours: int
    enabled: bool
    config: dict
    created_at: datetime
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    running: bool = False
    latest_run: Optional[JobRunBrief] = None


class JobRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    job_id: UUID
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
    trigger: str
    summary: Optional[dict] = None
    error: Optional[str] = None


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: str
    title: str
    body: str
    severity: str
    run_id: Optional[UUID] = None
    created_at: datetime
    acknowledged_at: Optional[datetime] = None


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