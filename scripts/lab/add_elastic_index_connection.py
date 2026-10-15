"""Add an Elastic connection that reuses the credentials of an existing one but reads another index pattern.

Run from the repository root (no secret is printed):
  PYTHONPATH=. venv/bin/python scripts/lab/add_elastic_index_connection.py \
      --from "Local Elastic (Metricbeat lab)" --name "Local Elastic (Auditbeat lab)" --index "auditbeat-*"
"""
import argparse
import asyncio

from sqlalchemy import select

from app.core.crypto import decrypt_config, encrypt_config
from app.core.database import async_session
from app.models import SIEMConnection


async def main(source: str, name: str, index: str) -> int:
    async with async_session() as db:
        existing = {c.name: c for c in (await db.execute(select(SIEMConnection))).scalars()}
        if name in existing:
            print(f"'{name}' already exists, nothing to do")
            return 0
        if source not in existing:
            print(f"no connection named '{source}'")
            return 1
        base = existing[source]
        config = decrypt_config(base.config_encrypted)
        config["index_pattern"] = index
        db.add(SIEMConnection(name=name, type=base.type, config_encrypted=encrypt_config(config),
                              created_by=base.created_by, is_active=True))
        await db.commit()
        print(f"added '{name}' reading {index}")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--from", dest="source", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--index", required=True)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.source, args.name, args.index)))
