"""FastAPI application entry point."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine
from app.api import auth, users, siem, hunts, findings, chat, sigma, investigations


# [explain] Runs once when the server starts and once when it stops
# [explain] (like unlocking the shop in the morning and locking it at night).
@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"🚀 {settings.APP_NAME} starting in {settings.APP_ENV} mode")
    yield
    await engine.dispose()
    print(f"🛑 {settings.APP_NAME} stopped")


# [explain] This creates the web server. Everything else (settings, addresses) gets attached to it.
app = FastAPI(
    title=settings.APP_NAME,
    description="Federated Multi-SIEM AI Threat Hunting Platform",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# [explain] CORS is a permission slip. It says: the website running at localhost:5173 (our Vue app)
# [explain] is allowed to talk to this server and to send its login cookie along.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
# [explain] Each line plugs one group of web addresses into the server, like plugging one room into a house.
# [explain] auth = login, users = accounts, siem = the connected SIEMs, hunts = searches, findings = what was found,
# [explain] chat = the AI helper, sigma = rule conversion, investigations = the hunt notebooks.
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(siem.router, prefix="/api/siem", tags=["siem"])
app.include_router(hunts.router, prefix="/api/hunts", tags=["hunts"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(chat.router, prefix="/api/chat", tags=["chat"])
app.include_router(sigma.router, prefix="/api/sigma", tags=["sigma"])
app.include_router(investigations.router, prefix="/api/investigations", tags=["investigations"])


# [explain] A tiny "are you alive?" address. A monitor can call it to check that the server is running.
@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV,
        "version": "0.1.0",
    }
