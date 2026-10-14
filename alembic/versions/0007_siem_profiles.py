"""latest data profile per SIEM connection"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007_siem_profiles"
down_revision = "0006_finding_priority"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "siem_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("siem_connection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("collected_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["siem_connection_id"], ["siem_connections.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["collected_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("siem_connection_id"),
    )


def downgrade():
    op.drop_table("siem_profiles")
