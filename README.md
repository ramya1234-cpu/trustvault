# TrustVault — Secure Document Sharing with Audit Trail

TrustVault is an enterprise-grade backend application for securely uploading, listing, searching, and sharing confidential documents with authenticated users. Built with defense-in-depth principles, it provides granular document-level permissions (owner, editor, reader), instant access revocation, administrator governance, and a tamper-evident SHA-256 cryptographic audit trail.

## Key Features

- **Authentication & Governance:**
  - Secure user registration with strict default `viewer` role assignment (prevents privilege escalation).
  - High-performance authentication using JWT with configurable token expiration.
  - Industry-standard password hashing using Argon2id via `pwdlib`.
  - Administrator endpoints for system-wide user governance, status toggles (active/inactive), and role management.
  - Safeguards against administrator lockout: prevents self-deactivation and demoting/deactivating the last active administrator.
- **Granular Document Lifecycle & Permissions:**
  - Authenticated multipart file upload with content-type whitelisting, file size restrictions (10 MB limit), and path containment.
  - Granular permissions: Owner (full control), Editor (`can_edit=True`, `can_read=True`), and Viewer (`can_read=True`, `can_edit=False`).
  - Owner-exclusive actions: sharing, revocation, document deletion, audit log access, and audit chain verification.
  - Safe physical file deletion with automatic permission cascade and permanent audit event preservation.
  - Protection against IDOR and existence leakage: outsiders attempting to view, update, or download unauthorized documents receive 404/403 responses without disclosing document existence or metadata.
- **Authorized Search & Filtering:**
  - High-performance, server-side search across documents (`GET /documents/search` and `GET /documents/`).
  - Filters by title keyword (`q`), exact category, owner ID, and ISO 8601 creation date ranges.
  - Strict authorization isolation: outsiders and revoked users receive zero results.
- **Tamper-Evident SHA-256 Audit Trail:**
  - Chronological cryptographic hash chaining linking every security-relevant event to the preceding event hash (genesis: `0` * 64).
  - Audit verification (`verify_audit_chain`) recalculates canonical JSON SHA-256 hashes from genesis, detecting altered fields, forged hashes, deleted events, or reordered records.
  - Owner-level verification (`GET /documents/{id}/audit/verify`) and system-wide administrator verification (`GET /admin/audit/verify`).
- **Database Migrations:**
  - Versioned, reviewed Alembic migrations supporting idempotent table creation, additive schema changes, and deterministic historical audit trail backfill.

## Technology Stack

- **Backend Framework:** Python 3.12, FastAPI 0.151.0, Starlette 1.9.0
- **Database & ORM:** PostgreSQL 17, SQLAlchemy 2.0.41, Psycopg 3.3.6 (psycopg-binary)
- **Database Migrations:** Alembic 1.20.0
- **Authentication & Cryptography:** PyJWT 2.15.1, Argon2-cffi 25.1.0, hashlib (SHA-256)
- **HTTP & Testing Client:** httpx2 2.16.0, httpcore2 2.16.0, pytest 9.1.1, anyio 4.15.1
- **Configuration & Validation:** Pydantic 2.14.1, Pydantic-Settings 2.16.0
- **Containerization:** Docker & Docker Compose (PostgreSQL 17 service)

## Project Structure

```text
trustvault/
├── alembic/
│   ├── env.py                  # Alembic environment runner loading app settings & models
│   ├── script.py.mako          # Revision template
│   └── versions/
│       ├── 0001_initial_schema.py                     # Baseline schema (users, docs, perms, audits)
│       └── 0002_add_updated_at_and_audit_hash_chain.py # Schema upgrade & audit chain backfill
├── app/
│   ├── admin.py                # Admin endpoints (user management, system audit, chain verify)
│   ├── audit.py                # SHA-256 hash chaining, canonical serialization, chain verification
│   ├── auth.py                 # User registration, login, JWT decode, current user dependency
│   ├── bootstrap_admin.py      # Secure CLI utility to bootstrap the initial administrator
│   ├── config.py               # Pydantic BaseSettings environment configuration
│   ├── database.py             # SQLAlchemy engine, session maker, connection health check
│   ├── documents.py            # Upload, search, list, download, update, delete, share, revoke
│   ├── init_db.py              # Baseline table initialization utility
│   ├── main.py                 # FastAPI application, lifespan handler, health endpoints
│   ├── models.py               # SQLAlchemy ORM declarative models
│   ├── schemas.py              # Pydantic validation and response schemas
│   └── security.py             # Password hashing (Argon2), JWT token creation and verification
├── tests/
│   ├── test_audit_chain.py     # Cryptographic audit hash-chain integrity & tamper detection
│   ├── test_auth.py            # Registration, login, JWT validation, token tampering
│   ├── test_document_lifecycle.py # Upload validation, metadata updates, deletion, path containment
│   ├── test_documents.py       # Sharing, revocation, download permissions, owner audit log
│   ├── test_migrations.py      # Alembic migration lifecycle, schema changes, historical backfill
│   ├── test_models_and_schemas.py # Model fields and Pydantic schema validation tests
│   ├── test_roles.py           # Role-based access control, admin endpoints, lockout safeguards
│   └── test_search.py          # Document search, category/date filters, authorization isolation
├── .env.example                # Safe environment variable configuration template
├── .gitignore                  # Git exclusions for secrets, venv, caches, and storage
├── alembic.ini                 # Alembic configuration
├── compose.yaml                # Docker Compose definition for local PostgreSQL 17
├── PROMPTS.md                  # Development and verification prompt history log
├── README.md                   # Project documentation and architectural guide
├── requirements.txt            # Pinned project dependencies (UTF-8 encoded)
└── THREATS.md                  # Comprehensive threat model, mitigations, and residual risks
```

## Prerequisites

- Python 3.12+ (tested with 3.12.10)
- Git
- Docker Desktop (optional, for local PostgreSQL container)

## Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/ramya1234-cpu/trustvault.git
cd trustvault
```

### 2. Virtual Environment Setup
Windows PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 4. Environment Variables Configuration
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Safe placeholder configuration in `.env`:
```env
# PostgreSQL connection URL (using psycopg driver)
DATABASE_URL=postgresql+psycopg://trustvault_app:local_dev_only_change_me@127.0.0.1:5433/trustvault

# Secret key for JWT generation and verification (at least 32 characters)
JWT_SECRET=replace_this_with_a_secure_random_key_of_at_least_32_characters
```
> [!IMPORTANT]
> Never commit `.env` or paste production credentials in logs, documentation, or source control.

### 5. Local PostgreSQL Database Setup
Start the local PostgreSQL container via Docker Compose:
```powershell
docker compose up -d db
docker compose ps
```
The database runs on `127.0.0.1:5433` (mapped from container port 5432) to avoid conflicts with default system PostgreSQL installations.

### 6. Database Migrations (Alembic)
Apply all versioned database migrations to bring the database schema up to date:
```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```
Migration commands overview:
- `alembic upgrade head`: Applies all pending schema migrations and backfills historical audit records.
- `alembic current`: Displays the current database revision.
- `alembic history`: Displays migration history.
- `alembic downgrade -1`: Rolls back the last applied migration.
- `alembic stamp 0001_initial_schema`: Marks baseline schema as applied for databases initialized before Alembic was introduced.

### 7. Run the Application
Start the Uvicorn development server:
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```
Endpoints:
- **Local API:** `http://127.0.0.1:8000`
- **Local Swagger UI:** `http://127.0.0.1:8000/docs`
- **Local Service Health:** `http://127.0.0.1:8000/health`
- **Local Database Health:** `http://127.0.0.1:8000/health/db`
- **Live Deployed API:** `https://trustvault-o3fn.onrender.com`
- **Live Swagger UI:** `https://trustvault-o3fn.onrender.com/docs`
- **Live Database Health:** `https://trustvault-o3fn.onrender.com/health/db`

### 8. Bootstrap Initial Administrator
Public registration always creates standard `viewer` accounts. To promote the first administrative user safely, use the CLI bootstrap utility:
```powershell
.\.venv\Scripts\python.exe -m app.bootstrap_admin admin@example.com
```

---

## API Reference & Authorization Rules

### Role-Based Access Control Summary

| Action | Viewer | Editor (Explicit Permission) | Document Owner | Administrator |
| :--- | :---: | :---: | :---: | :---: |
| Register & Login | Yes | Yes | Yes | Yes |
| Upload Document | Yes | Yes | Yes | Yes |
| Search / List Owned Documents | Yes | Yes | Yes | Yes |
| Search / List Shared Documents | If `can_read` | If `can_read` | N/A (Owns) | N/A |
| Download Document | If `can_read` | If `can_read` | Yes | No (Strict Isolation) |
| Update Document Metadata | No | If `can_edit` | Yes | No |
| Delete Document | No | No | **Yes** | No |
| Share Document & Grant Permissions | No | No | **Yes** | No |
| Revoke Document Permissions | No | No | **Yes** | No |
| View Document Audit Log & Verify | No | No | **Yes** | No |
| Manage System Users & Roles | No | No | No | **Yes** |
| View System Audit Metadata | No | No | No | **Yes** |
| Verify Global Audit Hash Chain | No | No | No | **Yes** |

### Core Endpoints

#### Authentication (`/auth`)
- `POST /auth/register`: Public registration. Always assigns `viewer` role.
- `POST /auth/login`: Authenticates user credentials, returns bearer JWT.
- `GET /auth/me`: Retrieves current user profile.

#### Document Management (`/documents`)
- `POST /documents/upload`: Multipart upload with content-type whitelist (`application/pdf`, `text/plain`, `image/png`, `image/jpeg`), size limit (10 MB), and safe UUID storage filename.
- `GET /documents/`: Lists documents accessible to the user (owned or shared with `can_read=True`).
- `GET /documents/search`: Multi-parameter search (`q`, `category`, `owner_id`, `start_date`, `end_date`, `limit`, `offset`) with authorization isolation.
- `GET /documents/{id}`: Retrieves document details (Owner or `can_read=True`; outsiders receive 404).
- `PATCH /documents/{id}`: Updates `title` or `category` (Owner or `can_edit=True`; read-only users receive 403, outsiders receive 404).
- `DELETE /documents/{id}`: Deletes document, removes permissions, and deletes storage file (**Owner-only**; editors receive 403, outsiders receive 403). Audit history is permanently preserved.
- `GET /documents/{id}/download`: Downloads document file (Owner or `can_read=True`). Validates path containment against `storage/` directory escape.
- `POST /documents/{id}/share`: Grants granular read/edit permissions (**Owner-only**). Prevents self-sharing and duplicate permissions.
- `DELETE /documents/{id}/share/{user_id}`: Revokes recipient access immediately (**Owner-only**).
- `GET /documents/{id}/audit`: Retrieves document audit trail (**Owner-only**).
- `GET /documents/{id}/audit/verify`: Verifies document audit hash chain (**Owner-only**).

#### Administration (`/admin`)
- `GET /admin/users`: Lists all system users (**Administrator-only**).
- `PATCH /admin/users/{user_id}/status`: Activates or deactivates user accounts (**Administrator-only**). Prevents self-deactivation and deactivating the last active administrator.
- `PATCH /admin/users/{user_id}/role`: Updates user role (`administrator`, `owner`, `viewer`) (**Administrator-only**). Prevents demoting the last active administrator.
- `GET /admin/audit`: Inspects system-wide audit metadata without disclosing document contents, passwords, or tokens (**Administrator-only**).
- `GET /admin/audit/verify`: Cryptographically verifies the entire system audit hash chain (**Administrator-only**).

---

## Interactive Demo & Evaluator Walkthrough

This step-by-step walkthrough allows an evaluator to test and verify all core capabilities using Swagger UI (`/docs`) or `curl`:

### Step 1: User Registration
Register three test accounts (all initially receive the safe `viewer` role):
```bash
# 1. Document Owner (Alice)
curl -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "full_name": "Alice Owner", "password": "StrongPassword123!"}'

# 2. Authorized Recipient (Bob)
curl -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "bob@example.com", "full_name": "Bob Recipient", "password": "StrongPassword123!"}'

# 3. Unauthorized Outsider (Eve)
curl -X POST "http://127.0.0.1:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "eve@example.com", "full_name": "Eve Outsider", "password": "StrongPassword123!"}'
```

### Step 2: Authentication & Token Acquisition
Log in with each account to obtain JWT Bearer access tokens:
```bash
# Obtain ALICE_TOKEN
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "StrongPassword123!"}'

# Obtain BOB_TOKEN
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "bob@example.com", "password": "StrongPassword123!"}'

# Obtain EVE_TOKEN
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "eve@example.com", "password": "StrongPassword123!"}'
```

### Step 3: Document Upload as Owner (Alice)
Upload a confidential document with title and category:
```bash
curl -X POST "http://127.0.0.1:8000/documents/upload?title=Confidential%20Security%20Plan&category=Security" \
  -H "Authorization: Bearer <ALICE_TOKEN>" \
  -F "file=@sample.txt"
# Returns: {"id": 1, "owner_id": 1, "title": "Confidential Security Plan", "category": "Security", ...}
```

### Step 4: Verify Unauthorized Access Blocking (Outsider Eve)
Demonstrate that unauthorized users cannot read or download:
```bash
# Unauthorized download attempt (Denied with HTTP 403)
curl -i -X GET "http://127.0.0.1:8000/documents/1/download" \
  -H "Authorization: Bearer <EVE_TOKEN>"

# Unauthorized details attempt (Returns HTTP 404 to prevent ID enumeration)
curl -i -X GET "http://127.0.0.1:8000/documents/1" \
  -H "Authorization: Bearer <EVE_TOKEN>"
```

### Step 5: Owner Shares Document with Bob
Alice explicitly grants read-only permission (`can_read=true`, `can_edit=false`) to Bob (`user_id=2`):
```bash
curl -X POST "http://127.0.0.1:8000/documents/1/share" \
  -H "Authorization: Bearer <ALICE_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 2, "can_read": true, "can_edit": false}'
# Returns HTTP 201: {"message": "Document shared successfully", ...}
```

### Step 6: Authorized Download & Search (Bob)
Bob can now search and download the document:
```bash
# Authorized search
curl -X GET "http://127.0.0.1:8000/documents/search?q=Security" \
  -H "Authorization: Bearer <BOB_TOKEN>"
# Returns document metadata with is_owner=false, can_read=true, can_edit=false

# Authorized download
curl -X GET "http://127.0.0.1:8000/documents/1/download" \
  -H "Authorization: Bearer <BOB_TOKEN>" \
  --output downloaded_sample.txt
```

### Step 7: Immediate Access Revocation
Alice revokes Bob's access. Bob immediately loses all access rights:
```bash
# Alice revokes Bob's permission
curl -X DELETE "http://127.0.0.1:8000/documents/1/share/2" \
  -H "Authorization: Bearer <ALICE_TOKEN>"
# Returns HTTP 204 No Content

# Bob attempts download immediately (Denied with HTTP 403)
curl -i -X GET "http://127.0.0.1:8000/documents/1/download" \
  -H "Authorization: Bearer <BOB_TOKEN>"

# Bob searches again (Returns empty list [], zero leakage)
curl -X GET "http://127.0.0.1:8000/documents/search?q=Security" \
  -H "Authorization: Bearer <BOB_TOKEN>"
```

### Step 8: Cryptographic Audit Chain Verification
Verify the SHA-256 tamper-evident audit trail for the document:
```bash
# Alice verifies document audit chain
curl -X GET "http://127.0.0.1:8000/documents/1/audit/verify" \
  -H "Authorization: Bearer <ALICE_TOKEN>"
# Returns:
# {
#   "is_valid": true,
#   "total_events": 5,
#   "verified_events": 5,
#   "message": "Audit chain verified successfully across 5 events.",
#   "tampered_event_id": null
# }
```

### Step 9: Administrator System-Wide Governance
Promote an administrator via CLI and inspect platform audit metadata:
```bash
# Bootstrap administrator
python -m app.bootstrap_admin alice@example.com

# Admin verifies platform-wide audit chain
curl -X GET "http://127.0.0.1:8000/admin/audit/verify" \
  -H "Authorization: Bearer <ALICE_TOKEN>"
# Returns verified audit chain status across all system events

# Admin inspects audit events without disclosing file contents or secrets
curl -X GET "http://127.0.0.1:8000/admin/audit" \
  -H "Authorization: Bearer <ALICE_TOKEN>"
```

---

## Testing & Quality Verification

Run the full automated test suite using the virtual environment:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

### Verified Test Results
```text
============================= 74 passed in 8.70s ==============================
```
- **Passed:** 74 tests
- **Failed:** 0
- **Warnings:** 0
- **Skipped:** 0

### Test Coverage Highlights
1. `tests/test_audit_chain.py` (9 tests): Valid sequence chaining, altered event field detection, altered hash detection, deleted event detection, reordered event detection, owner verification, non-owner denial.
2. `tests/test_auth.py` (4 tests): Password length validation, duplicate email conflict, valid/invalid/inactive login, JWT expiry, signature tampering (32+ byte keys), missing token handling.
3. `tests/test_document_lifecycle.py` (17 tests): Owner update, editor update, read-only denial, outsider 404, invalid metadata, owner deletion, editor deletion rejection, outsider deletion rejection, upload file size limits (HTTP 413), content-type whitelisting, empty file rejection, blank title rejection, path traversal protection, foreign-key safe deletion.
4. `tests/test_documents.py` (14 tests): Sharing authorization, revocation, download controls, duplicate share prevention, audit event generation on upload/share/revoke, owner audit log access, non-owner rejection.
5. `tests/test_migrations.py` (1 test): Full Alembic lifecycle test: legacy schema initialization, migration to head, column creation, historical audit record backfill with hash chain verification, downgrade, and re-upgrade.
6. `tests/test_models_and_schemas.py` (7 tests): Additive model fields (`updated_at`, `prev_hash`, `hash`), schema validation for roles and updates, backward compatibility of `DocumentResponse`.
7. `tests/test_roles.py` (13 tests): Registration self-escalation prevention, viewer restrictions on admin endpoints, admin user listing, activation/deactivation, inactive login prevention, self-deactivation lockout guard, last active admin protection, role assignment, last active admin demotion guard, system audit metadata inspection, global audit chain verify, bootstrap utility.
8. `tests/test_search.py` (9 tests): Search by title keyword, category, owner ID, date range, combined filters, pagination, strict authorization isolation (outsiders receive 0 results), shared document visibility, immediate revocation removal.

### Additional Quality Checks
- **Python Compilation:** `python -m compileall app tests alembic` passed with 0 errors.
- **Git Whitespace Check:** `git diff --check` passed cleanly with 0 whitespace warnings.

---

## Deployment & Operational Considerations

### Deployment Architecture
- **Hosted Environment:** Render Web Service (FastAPI) + Render PostgreSQL Managed Database.
- **Live Health Endpoint:** `https://trustvault-o3fn.onrender.com/health`
- **Live Database Health:** `https://trustvault-o3fn.onrender.com/health/db`
- **Swagger Documentation:** `https://trustvault-o3fn.onrender.com/docs`

### Deployment Steps & Migrations
1. Push reviewed commits to GitHub (`origin/main`).
2. Configure environment variables in Render Dashboard:
   - `DATABASE_URL` (Internal database connection string)
   - `JWT_SECRET` (Cryptographically secure random secret, >= 32 characters)
3. Run database migrations on the deployment target:
   ```bash
   alembic upgrade head
   ```
4. Confirm health endpoints return `{"status": "ok"}` and `{"database": "connected"}`.

### Known Risks & Operational Safeguards
1. **Cryptographic Chain Scope Limitation:**
   The SHA-256 hash chain provides tamper evidence against application-level modifications, API attacks, and unauthorized record alterations. However, a privileged database administrator or compromised database superuser with direct table write access could theoretically rewrite historical records and recalculate downstream hashes. For compliance environments, pair TrustVault's hash chain with write-once (WORM) storage or external log shipping (e.g., AWS CloudWatch, remote Syslog).
2. **Cold-Start Characteristics:**
   On free-tier hosting (e.g., Render free tier), the web service spins down after 15 minutes of inactivity. Initial requests may experience a 30–50 second cold-start latency.
3. **Storage Persistence:**
   In containerized deployments with ephemeral local filesystems, configure persistent volume mounts for the `storage/` directory or connect to object storage (e.g., S3/GCS) with pre-signed URLs to preserve files across redeployments.
