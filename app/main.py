"""FastAPI application entry point."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.csrf import csrf_ok
from app.core.database import engine
from app.api import auth, users, siem, hunts, findings, chat, sigma, investigations


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"🚀 {settings.APP_NAME} starting in {settings.APP_ENV} mode")
    yield
    await engine.dispose()
    print(f"🛑 {settings.APP_NAME} stopped")


app = FastAPI(
    title=settings.APP_NAME,
    description="Federated Multi-SIEM AI Threat Hunting Platform",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    if not csrf_ok(request.method, request.url.path, request.cookies, request.headers):
        return JSONResponse({"detail": "CSRF check failed: missing or wrong X-CSRF-Token"}, status_code=403)
    return await call_next(request)


# Routes
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(siem.router, prefix="/api/siem", tags=["siem"])
app.include_router(hunts.router, prefix="/api/hunts", tags=["hunts"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(chat.router, prefix="/api/chat", tags=["chat"])
app.include_router(sigma.router, prefix="/api/sigma", tags=["sigma"])
app.include_router(investigations.router, prefix="/api/investigations", tags=["investigations"])


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV,
        "version": "0.1.0",
    }
