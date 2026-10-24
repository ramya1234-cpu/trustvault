
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from app.admin import router as admin_router
from app.auth import router as auth_router
from app.documents import router as documents_router
from app.database import check_database, engine
from app.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create missing tables without deleting existing data.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="DocuGuard - TrustVault",
    version="0.1.0",
    lifespan=lifespan,
    swagger_ui_parameters={"persistAuthorization": True},
)

app.include_router(auth_router)
app.include_router(documents_router)
app.include_router(admin_router)


@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="theme-color" content="#0f172a">
        <title>DocuGuard | Secure Document Sharing</title>
        <style>
            * { box-sizing: border-box; }

            body {
                margin: 0;
                font-family: Arial, Helvetica, sans-serif;
                background: #f8fafc;
                color: #0f172a;
            }

            nav {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 22px 8%;
                background: #ffffff;
                border-bottom: 1px solid #e2e8f0;
            }

            .brand {
                font-size: 23px;
                font-weight: 800;
                color: #2563eb;
            }

            .nav-link {
                color: #334155;
                text-decoration: none;
                font-weight: 600;
            }

            .hero {
                min-height: 75vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                text-align: center;
                padding: 65px 20px;
                background:
                    radial-gradient(ellipse at top, #dbeafe 0%, transparent 65%),
                    #f8fafc;
            }

            .tag {
                background: #dbeafe;
                color: #1d4ed8;
                padding: 8px 14px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: 700;
            }

            h1 {
                max-width: 800px;
                font-size: clamp(38px, 6vw, 64px);
                line-height: 1.1;
                margin: 24px 0 18px;
                letter-spacing: -2px;
            }

            h1 span { color: #2563eb; }

            .description {
                max-width: 650px;
                color: #475569;
                font-size: 18px;
                line-height: 1.8;
            }

            .actions {
                display: flex;
                gap: 14px;
                flex-wrap: wrap;
                justify-content: center;
                margin-top: 25px;
            }

            .button {
                display: inline-block;
                padding: 14px 22px;
                border-radius: 9px;
                text-decoration: none;
                font-weight: 700;
            }

            .primary {
                background: #2563eb;
                color: #ffffff;
            }

            .secondary {
                border: 1px solid #cbd5e1;
                color: #0f172a;
                background: #ffffff;
            }

            .features {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 20px;
                max-width: 1050px;
                margin: -10px auto 60px;
                padding: 0 20px;
            }

            .feature {
                background: #ffffff;
                padding: 25px;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }

            .feature h2 { font-size: 18px; }

            .feature p {
                color: #64748b;
                line-height: 1.7;
                font-size: 14px;
            }

            footer {
                text-align: center;
                padding: 25px;
                color: #64748b;
                border-top: 1px solid #e2e8f0;
                font-size: 13px;
            }

            @media (max-width: 650px) {
                nav { padding: 18px 5%; }
                .features { grid-template-columns: 1fr; }
                h1 { letter-spacing: -1px; }
            }
        </style>
    </head>
    <body>
        <nav>
            <div class="brand">🔐 DocuGuard</div>
            <a class="nav-link" href="/docs">API Docs ↗</a>
        </nav>

        <main>
            <section class="hero">
                <div class="tag">SECURE DOCUMENT MANAGEMENT</div>

                <h1>Your documents.<br>
                    <span>Your control.</span>
                </h1>

                <p class="description">
                    A secure document-sharing platform built to manage access,
                    control permissions, revoke shared access, and maintain
                    tamper-evident audit records.
                </p>

                <div class="actions">
                    <a class="button primary" href="/docs">
                        Explore the API →
                    </a>
                    <a class="button secondary" href="/health/db">
                        Check Database Status
                    </a>
                </div>
            </section>

            <section class="features">
                <article class="feature">
                    <h2>🛡️ Access Control</h2>
                    <p>
                        Backend-enforced permissions help ensure that
                        only authorized users can access documents.
                    </p>
                </article>

                <article class="feature">
                    <h2>🔑 Sharing & Revocation</h2>
                    <p>
                        Manage document sharing and revoke permissions
                        through the platform's API.
                    </p>
                </article>

                <article class="feature">
                    <h2>📋 Audit Trail</h2>
                    <p>
                        Maintain audit records designed to help detect
                        unauthorized changes to recorded events.
                    </p>
                </article>
            </section>
        </main>

        <footer>
            DocuGuard · Powered by TrustVault API
        </footer>
    </body>
    </html>
    """


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/db")
def database_health():
    try:
        check_database()
        return {"database": "connected"}
    except Exception as exc:
        print(
            f"Database health check failed: {type(exc).__name__}",
            flush=True,
        )
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        ) from exc
