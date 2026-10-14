"""link findings that several SIEMs reported for the same behaviour"""
import sqlalchemy as sa
from alembic import op

revision = "0004_finding_correlation"
down_revision = "0003_group_findings"
branch_labels = None
depends_on = None


# [explain] Adds a shared id so findings that two SIEMs reported for the same behaviour can be linked.
def upgrade():
    op.add_column("hunt_results", sa.Column("correlation_id", sa.Text(), nullable=True))
    op.create_index("idx_results_correlation", "hunt_results", ["correlation_id"], unique=False)


# [explain] Removes it.
def downgrade():
    op.drop_index("idx_results_correlation", table_name="hunt_results")
    op.drop_column("hunt_results", "correlation_id")
