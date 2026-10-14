"""analyst suppressions: known-benign patterns hidden in future hunts"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_finding_suppressions"
down_revision = "0004_finding_correlation"
branch_labels = None
depends_on = None


# [explain] Creates the table of "known benign" decisions and the link from findings to it.
def upgrade():
    op.create_table(
        "finding_suppressions",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["revoked_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint"),
    )
    op.add_column("hunt_results", sa.Column("suppression_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_results_suppression", "hunt_results", "finding_suppressions",
        ["suppression_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index("idx_results_suppression", "hunt_results", ["suppression_id"], unique=False)


# [explain] Drops that table and link.
def downgrade():
    op.drop_index("idx_results_suppression", table_name="hunt_results")
    op.drop_constraint("fk_results_suppression", "hunt_results", type_="foreignkey")
    op.drop_column("hunt_results", "suppression_id")
    op.drop_table("finding_suppressions")
