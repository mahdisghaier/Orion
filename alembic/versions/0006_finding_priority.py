"""deterministic priority score (with its breakdown) stored on each finding"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_finding_priority"
down_revision = "0005_finding_suppressions"
branch_labels = None
depends_on = None


# [explain] Adds the priority score and the list of reasons to every finding.
def upgrade():
    op.add_column("hunt_results", sa.Column("priority_score", sa.Integer(), nullable=True))
    op.add_column("hunt_results", sa.Column("priority_breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_index("idx_results_priority", "hunt_results", ["priority_score"], unique=False)


# [explain] Removes them.
def downgrade():
    op.drop_index("idx_results_priority", table_name="hunt_results")
    op.drop_column("hunt_results", "priority_breakdown")
    op.drop_column("hunt_results", "priority_score")
