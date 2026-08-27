"""Async database engine + session factory.

Usage in route handlers:
    async def get_db():
        async with async_session() as session:
            yield session

    @router.get("/things")
    async def list_things(db: AsyncSession = Depends(get_db)):
        result = await db.execute(select(Thing))
        return result.scalars().all()
"""
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# Async engine — connection pool managed by SQLAlchemy
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.APP_DEBUG,  # log SQL statements in dev
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # verify connection is alive before checkout
)

# Session factory — produces AsyncSession instances
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # don't re-fetch objects after commit (async-friendly)
)


class Base(DeclarativeBase):
    """Declarative base — all models inherit from this."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a database session per request.

    Usage:
        @router.get("/")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
