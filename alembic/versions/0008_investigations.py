"""investigations (hunt records) and their steps"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0008_investigations"
down_revision = "0007_siem_profiles"
branch_labels = None
depends_on = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


# [explain] Creates the hunt notebooks: investigations and their steps.
def upgrade():
    op.create_table(
        "investigations",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="open", nullable=False),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.Column("conclusion", sa.Text(), nullable=True),
        sa.Column("siem_targets", postgresql.ARRAY(UUID), nullable=False),
        sa.Column("time_range", JSONB, nullable=True),
        sa.Column("source_finding_id", UUID, nullable=True),
        sa.Column("created_by", UUID, nullable=False),
        sa.Column("concluded_by", UUID, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("concluded_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('open','concluded')", name="ck_investigation_status"),
        sa.CheckConstraint(
            "verdict IS NULL OR verdict IN ('true_positive','false_positive','inconclusive')",
            name="ck_investigation_verdict",
        ),
        sa.ForeignKeyConstraint(["source_finding_id"], ["hunt_results.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["concluded_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "investigation_steps",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("investigation_id", UUID, nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("proposed_by", sa.Text(), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("assessment", JSONB, nullable=True),
        sa.Column("status", sa.Text(), server_default="proposed", nullable=False),
        sa.Column("decided_by", UUID, nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_comment", sa.Text(), nullable=True),
        sa.Column("hunt_id", UUID, nullable=True),
        sa.Column("result", JSONB, nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("kind IN ('rule','pivot')", name="ck_step_kind"),
        sa.CheckConstraint("proposed_by IN ('ai','system','analyst')", name="ck_step_proposed_by"),
        sa.CheckConstraint(
            "status IN ('proposed','approved','rejected','executed','failed')", name="ck_step_status"
        ),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["hunt_id"], ["hunts.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "seq", name="uq_step_seq"),
    )
    op.create_index("idx_steps_investigation", "investigation_steps", ["investigation_id"], unique=False)


# [explain] Drops them.
def downgrade():
    op.drop_index("idx_steps_investigation", table_name="investigation_steps")
    op.drop_table("investigation_steps")
    op.drop_table("investigations")
