
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from app.auth import router as auth_router
from app.documents import router as documents_router
from app.database import check_database, engine
from app.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create any missing database tables when the service starts.
    # Existing tables and their data are preserved.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="TrustVault",
    version="0.1.0",
    lifespan=lifespan,
    swagger_ui_parameters={"persistAuthorization": True},
)

app.include_router(auth_router)
app.include_router(documents_router)


@app.get("/")
def root():
    return {"message": "TrustVault API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/db")
def database_health():
    try:
        check_database()
        return {"database": "connected"}
    except Exception as exc:
        # Log the actual error without returning credentials to the client.
        print(
            f"Database health check failed: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        ) from exc
