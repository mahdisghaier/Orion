"""scheduled jobs, their runs, notifications, and the threat-intelligence feed cache"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_scheduled_jobs"
down_revision = "0008_investigations"
branch_labels = None
depends_on = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade():
    op.create_table(
        "scheduled_jobs",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("config", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_by", UUID, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("kind IN ('threat_intel')", name="ck_job_kind"),
        sa.CheckConstraint("interval_hours BETWEEN 1 AND 336", name="ck_job_interval"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "job_runs",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("job_id", UUID, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), server_default="running", nullable=False),
        sa.Column("trigger", sa.Text(), server_default="schedule", nullable=False),
        sa.Column("summary", JSONB, nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint("status IN ('running','findings','clear','incomplete','error')", name="ck_run_status"),
        sa.CheckConstraint("trigger IN ('schedule','manual')", name="ck_run_trigger"),
        sa.ForeignKeyConstraint(["job_id"], ["scheduled_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_runs_job", "job_runs", ["job_id"], unique=False)
    op.create_table(
        "notifications",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), server_default="info", nullable=False),
        sa.Column("run_id", UUID, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", UUID, nullable=True),
        sa.CheckConstraint("severity IN ('info','warning','critical')", name="ck_notification_severity"),
        sa.ForeignKeyConstraint(["run_id"], ["job_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_notifications_created", "notifications", ["created_at"], unique=False)
    op.create_table(
        "intel_cache",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.PrimaryKeyConstraint("source"),
    )


def downgrade():
    op.drop_table("intel_cache")
    op.drop_index("idx_notifications_created", table_name="notifications")
    op.drop_table("notifications")
    op.drop_index("idx_runs_job", table_name="job_runs")
    op.drop_table("job_runs")
    op.drop_table("scheduled_jobs")
