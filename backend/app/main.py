import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan resources."""
    # Initialize worker-local scan concurrency limiter (10 permits per worker process)
    app.state.scan_semaphore = asyncio.Semaphore(10)
    yield
    # Clean up concurrency resources on shutdown
    app.state.scan_semaphore = None


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Backend API for WebVulnScanner web application vulnerability assessment platform."
    ),
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure CORS for local development and frontend clients
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Mount versioned API router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["General"])
async def root():
    """Root endpoint returning basic application metadata."""
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["Health"])
@app.get(f"{settings.API_V1_STR}/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify backend service readiness."""
    return {
        "status": "ok",
        "app": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }
