"""allow wazuh siem type"""
from alembic import op

revision = "0002_allow_wazuh"
down_revision = "cb9acf58af4d"
branch_labels = None
depends_on = None

NEW = "IN ('sentinel','elastic','wazuh')"
OLD = "IN ('sentinel','elastic')"


def upgrade():
    op.drop_constraint("ck_siem_type", "siem_connections", type_="check")
    op.create_check_constraint("ck_siem_type", "siem_connections", "type " + NEW)
    op.drop_constraint("ck_results_siem_type", "hunt_results", type_="check")
    op.create_check_constraint("ck_results_siem_type", "hunt_results", "siem_type " + NEW)


def downgrade():
    op.drop_constraint("ck_siem_type", "siem_connections", type_="check")
    op.create_check_constraint("ck_siem_type", "siem_connections", "type " + OLD)
    op.drop_constraint("ck_results_siem_type", "hunt_results", type_="check")
    op.create_check_constraint("ck_results_siem_type", "hunt_results", "siem_type " + OLD)
