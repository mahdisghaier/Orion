"""Seed script — creates initial users for testing.

Run with:
    python scripts/seed.py

Creates:
    admin@orion.local  / Admin123!        (admin)
    l1@orion.local      / L1analyst!      (soc_l1)
    l2@orion.local      / L2analyst!      (soc_l2)
    l3@orion.local      / L3analyst!      (soc_l3)
"""
import asyncio
from sqlalchemy import select

from app.core.database import async_session, engine
from app.core.security import hash_password
from app.models import User, Base


# [explain] The demo accounts, one per role (admin, soc_l1, soc_l2, soc_l3). They are only for local testing.
SEED_USERS = [
    {
        "email": "admin@orion.local",
        "full_name": "ORION Admin",
        "role": "admin",
        "password": "Admin123!",
    },
    {
        "email": "l1@orion.local",
        "full_name": "L1 Analyst",
        "role": "soc_l1",
        "password": "L1analyst!",
    },
    {
        "email": "l2@orion.local",
        "full_name": "L2 Analyst",
        "role": "soc_l2",
        "password": "L2analyst!",
    },
    {
        "email": "l3@orion.local",
        "full_name": "L3 Analyst",
        "role": "soc_l3",
        "password": "L3analyst!",
    },
]


# [explain] Creates the demo accounts above, skipping any that already exist, so it is safe to run twice.
async def seed():
    async with async_session() as db:
        for user_data in SEED_USERS:
            # Check if user already exists
            result = await db.execute(
                select(User).where(User.email == user_data["email"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                print(f"  ⏭️  {user_data['email']} already exists — skipping")
                continue

            user = User(
                email=user_data["email"],
                full_name=user_data["full_name"],
                role=user_data["role"],
                password_hash=hash_password(user_data["password"]),
            )
            db.add(user)
            print(f"  ✅ Created {user_data['email']} ({user_data['role']})")

        await db.commit()

    await engine.dispose()
    print("\n🎉 Seed complete. You can now login with any of the seeded users.")


if __name__ == "__main__":
    print("Seeding ORION database...")
    asyncio.run(seed())
