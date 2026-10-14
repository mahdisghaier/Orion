"""SQLAlchemy 2.0 async models for ORION.

All 11 tables from the architecture brief V1.1:
  Core:     users, siem_connections, sigma_rules, hunts, hunt_results, incidents
  Audit:    audit_log, llm_audit
  Response: interventions
  Feedback: analyst_feedback, mitre_coverage

Import pattern:
    from app.models import User, Hunt, HuntResult, ...
"""
from datetime import datetime
from typing import Optional, List
import uuid

from sqlalchemy import (
    String, Text, Boolean, Integer, BigInteger, Numeric,
    DateTime, ForeignKey, CheckConstraint, UniqueConstraint,
    Index, func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


# ─────────────────────────────────────────────────────────────────
# 1. USERS & RBAC
# ─────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="admin | soc_l1 | soc_l2 | soc_l3"
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin','soc_l1','soc_l2','soc_l3')",
            name="ck_users_role"
        ),
    )

    # Relationships
    hunts_created: Mapped[List["Hunt"]] = relationship(
        back_populates="creator", foreign_keys="Hunt.created_by"
    )
    reviews: Mapped[List["HuntResult"]] = relationship(
        back_populates="reviewer", foreign_keys="HuntResult.reviewed_by"
    )


# ─────────────────────────────────────────────────────────────────
# 2. SIEM CONNECTIONS
# ─────────────────────────────────────────────────────────────────
class SIEMConnection(Base):
    __tablename__ = "siem_connections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(
        Text, nullable=False, comment="sentinel | elastic | wazuh"
    )
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("type IN ('sentinel','elastic','wazuh')", name="ck_siem_type"),
    )


# ─────────────────────────────────────────────────────────────────
# 3. SIGMA RULES (with lifecycle tracking)
# ─────────────────────────────────────────────────────────────────
class SigmaRule(Base):
    __tablename__ = "sigma_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    rule_uuid: Mapped[Optional[str]] = mapped_column(Text, unique=True, nullable=True)
    yaml: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(
        Text, nullable=False, comment="community | custom"
    )
    parent_rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sigma_rules.id"), nullable=True
    )
    mitre_tactics: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    mitre_techniques: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    author: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Lifecycle (AGIE-inspired detection engineering discipline)
    lifecycle_status: Mapped[str] = mapped_column(
        Text, server_default="active", nullable=False
    )
    false_positive_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    true_positive_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    last_evaluated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("source IN ('community','custom')", name="ck_sigma_source"),
        CheckConstraint(
            "lifecycle_status IN ('draft','testing','active','deprecated','retired')",
            name="ck_sigma_lifecycle"
        ),
        Index("idx_sigma_mitre", "mitre_tactics", "mitre_techniques", postgresql_using="gin"),
        Index("idx_sigma_tags", "tags", postgresql_using="gin"),
        Index("idx_sigma_lifecycle", "lifecycle_status"),
    )


# ─────────────────────────────────────────────────────────────────
# 4. HUNTS
# ─────────────────────────────────────────────────────────────────
class Hunt(Base):
    __tablename__ = "hunts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sigma_rules.id"), nullable=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    siem_targets: Mapped[List[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    queries: Mapped[dict] = mapped_column(JSONB, nullable=False)
    time_range: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    total_hits: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hunt_type: Mapped[str] = mapped_column(
        Text, server_default="sigma", nullable=False,
        comment="sigma | kestrel"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','running','completed','failed','cancelled')",
            name="ck_hunts_status"
        ),
        CheckConstraint(
            "hunt_type IN ('sigma','kestrel')",
            name="ck_hunts_hunt_type"
        ),
        Index("idx_hunts_status", "status"),
        Index("idx_hunts_creator", "created_by"),
    )

    # Relationships
    creator: Mapped["User"] = relationship(
        back_populates="hunts_created", foreign_keys=[created_by]
    )
    results: Mapped[List["HuntResult"]] = relationship(
        back_populates="hunt", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────
# 5. HUNT RESULTS / FINDINGS
# ─────────────────────────────────────────────────────────────────
class HuntResult(Base):
    __tablename__ = "hunt_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    hunt_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunts.id", ondelete="CASCADE"), nullable=False
    )
    siem_connection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("siem_connections.id"), nullable=True
    )
    siem_type: Mapped[str] = mapped_column(Text, nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Extracted ECS fields (indexed for fast filtering)
    source_ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    host_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process_command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Grouping: repeated samples of the same behaviour are one finding (see services/grouping.py).
    # event_time / ecs_event describe the most recent occurrence.
    fingerprint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, server_default="1", nullable=False)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Findings of the same hunt that different SIEMs reported for the same behaviour share this id
    # (see services/correlation.py).
    correlation_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Full ECS event (flexible, for display + AI analysis)
    ecs_event: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Raw event as SIEM returned it (forensic reference)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # MITRE mapping (Layer 4 output)
    mitre_techniques: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    mitre_mapping_source: Mapped[str] = mapped_column(
        Text, server_default="explicit", nullable=False,
        comment="explicit (from Sigma tags) | llm_inferred (RAM approach)"
    )

    # Analyst workflow
    analyst_status: Mapped[str] = mapped_column(Text, server_default="new", nullable=False)
    analyst_comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "analyst_status IN ('new','validated','false_positive','escalated')",
            name="ck_results_status"
        ),
        CheckConstraint("siem_type IN ('sentinel','elastic','wazuh')", name="ck_results_siem_type"),
        CheckConstraint(
            "mitre_mapping_source IN ('explicit','llm_inferred')",
            name="ck_results_mitre_src"
        ),
        Index("idx_results_hunt", "hunt_id"),
        Index("idx_results_fingerprint", "fingerprint"),
        Index("idx_results_correlation", "correlation_id"),
        Index("idx_results_time_desc", "event_time", postgresql_ops={"event_time": "DESC"}),
        Index("idx_results_siem", "siem_type"),
        Index("idx_results_status", "analyst_status"),
        Index("idx_results_src_ip", "source_ip"),
        Index("idx_results_host", "host_name"),
        Index("idx_results_user", "user_name"),
        Index("idx_results_ecs", "ecs_event", postgresql_using="gin"),
        Index("idx_results_mitre", "mitre_techniques", postgresql_using="gin"),
    )

    # Relationships
    hunt: Mapped["Hunt"] = relationship(back_populates="results")
    reviewer: Mapped[Optional["User"]] = relationship(
        back_populates="reviews", foreign_keys=[reviewed_by]
    )


# ─────────────────────────────────────────────────────────────────
# 6. INCIDENTS
# ─────────────────────────────────────────────────────────────────
class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, server_default="open", nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_tactics: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    mitre_techniques: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('open','investigating','contained','closed')",
            name="ck_incidents_status"
        ),
        CheckConstraint(
            "severity IN ('low','medium','high','critical')",
            name="ck_incidents_severity"
        ),
    )


# ─────────────────────────────────────────────────────────────────
# 7. AUDIT LOG (general — every state-changing user action)
# ─────────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_audit_time_desc", "timestamp", postgresql_ops={"timestamp": "DESC"}),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_action", "action"),
    )


# ─────────────────────────────────────────────────────────────────
# 8. LLM AUDIT (hallucination mitigation — every LLM call logged)
# ─────────────────────────────────────────────────────────────────
class LLMAudit(Base):
    __tablename__ = "llm_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    hunt_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunts.id"), nullable=True
    )
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunt_results.id"), nullable=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    chat_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)

    # The grounding (what was sent to the LLM)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    retrieved_context: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # The raw output (forensic reference)
    raw_response: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_response: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # LLM metadata
    model: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    token_count_prompt: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    token_count_response: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Confidence + validation (hallucination mitigation)
    overall_confidence: Mapped[Optional[float]] = mapped_column(Numeric(3, 2), nullable=True)
    was_rejected: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_llm_audit_finding", "finding_id"),
        Index("idx_llm_audit_hunt", "hunt_id"),
        Index("idx_llm_audit_time", "created_at", postgresql_ops={"created_at": "DESC"}),
        Index("idx_llm_audit_rejected", "was_rejected"),
    )


# ─────────────────────────────────────────────────────────────────
# 9. INTERVENTIONS (tiered lifecycle)
# ─────────────────────────────────────────────────────────────────
class Intervention(Base):
    __tablename__ = "interventions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunt_results.id", ondelete="CASCADE"), nullable=True
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True
    )
    tier: Mapped[int] = mapped_column(Integer, nullable=False, comment="1 | 2 | 3")
    playbook_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_actions: Mapped[dict] = mapped_column(JSONB, nullable=False)
    llm_confidence: Mapped[float] = mapped_column(Numeric(3, 2), nullable=False)
    llm_rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, server_default="proposed", nullable=False)
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    rolled_back_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("tier IN (1, 2, 3)", name="ck_intervention_tier"),
        CheckConstraint(
            "status IN ('proposed','pre_staged','approved','rejected',"
            "'executed','rolled_back','failed')",
            name="ck_intervention_status"
        ),
        CheckConstraint(
            "llm_confidence >= 0.0 AND llm_confidence <= 1.0",
            name="ck_intervention_confidence"
        ),
        Index("idx_intervention_status", "status"),
        Index("idx_intervention_tier", "tier"),
        Index("idx_intervention_finding", "finding_id"),
    )


# ─────────────────────────────────────────────────────────────────
# 10. ANALYST FEEDBACK (TP/FP labels for calibration)
# ─────────────────────────────────────────────────────────────────
class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunt_results.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    label: Mapped[str] = mapped_column(
        Text, nullable=False, comment="true_positive | false_positive | uncertain"
    )
    llm_confidence_at_time: Mapped[Optional[float]] = mapped_column(Numeric(3, 2), nullable=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "label IN ('true_positive','false_positive','uncertain')",
            name="ck_feedback_label"
        ),
        UniqueConstraint("finding_id", "user_id", name="uq_feedback_per_user"),
        Index("idx_feedback_finding", "finding_id"),
        Index("idx_feedback_label", "label"),
    )


# ─────────────────────────────────────────────────────────────────
# 11. MITRE COVERAGE (technique coverage tracking)
# ─────────────────────────────────────────────────────────────────
class MITRECoverage(Base):
    __tablename__ = "mitre_coverage"

    technique_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tactic: Mapped[str] = mapped_column(Text, nullable=False)
    technique_name: Mapped[str] = mapped_column(Text, nullable=False)
    subtechnique_of: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    detection_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    last_hunted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_in_finding_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
    platforms: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_mitre_tactic", "tactic"),
        Index("idx_mitre_rule_count", "rule_count"),
    )
