"""clients: every connection, hunt, finding, investigation, job and suppression belongs to one client"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010_clients"
down_revision = "0009_scheduled_jobs"
branch_labels = None
depends_on = None

UUID = postgresql.UUID(as_uuid=True)
TABLES = ["users", "siem_connections", "hunts", "hunt_results", "investigations", "scheduled_jobs",
          "notifications", "finding_suppressions", "incidents"]


def upgrade():
    op.create_table(
        "clients",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    for table in TABLES:
        op.add_column(table, sa.Column("client_id", UUID, nullable=True))
        op.create_foreign_key(f"fk_{table}_client", table, "clients", ["client_id"], ["id"])
        op.create_index(f"ix_{table}_client_id", table, ["client_id"])
    # the data that already exists belongs to one default client; users stay platform-wide
    op.execute("INSERT INTO clients (name) VALUES ('Default client')")
    for table in TABLES:
        if table != "users":
            op.execute(f"UPDATE {table} SET client_id = (SELECT id FROM clients WHERE name = 'Default client')")


def downgrade():
    for table in reversed(TABLES):
        op.drop_index(f"ix_{table}_client_id", table_name=table)
        op.drop_constraint(f"fk_{table}_client", table, type_="foreignkey")
        op.drop_column(table, "client_id")
    op.drop_table("clients")
