"""group repeated events into one finding"""
import sqlalchemy as sa
from alembic import op

revision = "0003_group_findings"
down_revision = "0002_allow_wazuh"
branch_labels = None
depends_on = None


# [explain] Adds the columns that let many identical events become one finding: fingerprint, how many times, first and last time.
def upgrade():
    op.add_column("hunt_results", sa.Column("fingerprint", sa.Text(), nullable=True))
    op.add_column("hunt_results", sa.Column("occurrence_count", sa.Integer(), server_default="1", nullable=False))
    op.add_column("hunt_results", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("hunt_results", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.create_index("idx_results_fingerprint", "hunt_results", ["fingerprint"], unique=False)


# [explain] Removes those columns.
def downgrade():
    op.drop_index("idx_results_fingerprint", table_name="hunt_results")
    op.drop_column("hunt_results", "last_seen")
    op.drop_column("hunt_results", "first_seen")
    op.drop_column("hunt_results", "occurrence_count")
    op.drop_column("hunt_results", "fingerprint")
