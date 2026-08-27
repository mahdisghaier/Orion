"""One-off script to create the first admin user.

Run with:
    python -m scripts.create_admin
"""
import asyncio
from app.core.database import async_session
from app.core.security import hash_password
from app.models import User


async def create_admin():
    email = input("Admin email: ").strip()
    full_name = input("Full name: ").strip()
    password = input("Password: ").strip()

    async with async_session() as db:
        user = User(
            email=email,
            full_name=full_name,
            role="admin",
            password_hash=hash_password(password),
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        print(f"\n✅ Admin user created: {user.email} (id={user.id})")


if __name__ == "__main__":
    asyncio.run(create_admin())