# TrustVault — Threat Model and Security Assessment

## 1. Overview

TrustVault is a secure, enterprise document-sharing backend built with Python 3.12, FastAPI, SQLAlchemy 2, PostgreSQL 17, and Alembic. It provides authenticated document upload, granular role and permission management, search isolation, immediate access revocation, and an append-only, tamper-evident SHA-256 cryptographic audit trail.

This document identifies key assets, trust boundaries, threat scenarios, implemented mitigations, supporting automated tests, and residual operational risks.

---

## 2. Assets to Protect

1. **User Credentials & Access Tokens:**
   - Plaintext passwords (must never be stored, logged, or exposed).
   - Password hashes (stored using Argon2id).
   - JWT access tokens, token signatures, and HMAC secret keys.
2. **Confidential Documents & Files:**
   - Document metadata (titles, categories, ownership relations).
   - Physical document content stored on disk.
   - Storage directory structure and paths (must not escape or leak).
3. **Authorization & Access Control Records:**
   - Document ownership and granular permissions (`can_read`, `can_edit`).
   - User account status (`is_active`) and system role (`administrator`, `owner`, `viewer`).
4. **Audit Trail & Evidence Integrity:**
   - Historical audit records detailing uploads, shares, revocations, edits, downloads, and denied access attempts.
   - SHA-256 hash chains linking events from genesis.
5. **System & Infrastructure Secrets:**
   - PostgreSQL connection strings and database credentials.
   - Server environment variables and configuration files (`.env`).

---

## 3. Trust Boundaries

- **Client to API (Untrusted Boundary):** All incoming HTTP requests, headers, query parameters, multipart payloads, and JSON bodies are untrusted and strictly validated via Pydantic schemas and FastAPI dependencies.
- **Authentication Boundary:** Endpoints requiring authentication validate bearer JWT signatures, expiration, and active user account state. Inactive or deleted accounts are immediately rejected.
- **Authorization Boundary (Object-Level Access Control):** The backend enforces document-level permissions (Owner vs. Editor vs. Viewer vs. Outsider) on every read, write, update, delete, and download operation.
- **Administrative Boundary:** Administrative endpoints are isolated behind `require_admin`. Non-administrators are denied with 403 Forbidden and the attempt is recorded in the audit trail.
- **Filesystem / Storage Boundary:** Uploaded files are quarantined in a designated `storage/` directory with randomized UUID filenames. All path access is validated against directory traversal and path escape.
- **Audit Logging Boundary:** The audit log is append-only. Cryptographic hash chaining prevents retroactive tampering, deletion, or reordering without detection.

---

## 4. Threat Scenarios, Mitigations, and Supporting Tests

### T1. Unauthorized Document Access and IDOR
- **Threat:** An attacker attempts to read, view, or enumerate confidential documents owned by other users or organizations by guessing or brute-forcing document IDs.
- **Potential Impact:** Breach of confidentiality and unauthorized disclosure of sensitive business or personal documents.
- **Mitigations Implemented:**
  - Document details (`GET /documents/{id}`) and update (`PATCH /documents/{id}`) enforce server-side ownership or explicit `can_read` permissions.
  - Non-authorized users (outsiders) receive HTTP 404 Not Found rather than 403 Forbidden to prevent document existence enumeration.
  - Document listing (`GET /documents/`) and search (`GET /documents/search`) execute SQL joins filtered strictly to owned documents or documents with active `can_read=True` permissions.
- **Supporting Tests:**
  - `tests/test_document_lifecycle.py::test_get_document_details` (outsider gets 404)
  - `tests/test_document_lifecycle.py::test_outsider_cannot_update_document` (returns 404)
  - `tests/test_search.py::test_search_authorization_isolation_outsider_gets_zero` (outsider gets 0 search results)

---

### T2. Access After Revocation
- **Threat:** A previously authorized recipient continues to view, search, or download a document after the owner has revoked their access.
- **Potential Impact:** Ongoing unauthorized disclosure of confidential documents after business relationships terminate.
- **Mitigations Implemented:**
  - Revocation (`DELETE /documents/{id}/share/{user_id}`) immediately deletes the permission row in the database.
  - All read, search, and download operations execute real-time database queries without caching stale permissions.
  - Revoked users immediately lose access across listing, search, details, and download endpoints.
- **Supporting Tests:**
  - `tests/test_documents.py::test_revoked_recipient_no_longer_sees_document`
  - `tests/test_documents.py::test_revoked_recipient_cannot_download_document`
  - `tests/test_search.py::test_revoked_recipient_cannot_see_document_in_search`

---

### T3. Privilege Escalation and Account Governance Bypass
- **Threat:** A malicious user registers with administrator privileges, or an attacker attempts to access administrative endpoints or deactivate all administrators to cause a permanent lockout.
- **Potential Impact:** Full system takeover, administrative lockout, or unauthorized user manipulation.
- **Mitigations Implemented:**
  - Public registration (`POST /auth/register`) hardcodes role assignment to `viewer`, ignoring client-supplied role payloads.
  - Administrative endpoints (`/admin/*`) require `require_admin` dependency.
  - Self-deactivation safeguard: administrators cannot deactivate their own account.
  - Last administrator safeguard: system prevents deactivating or demoting the last active administrator.
  - Inactive accounts cannot log in or authenticate with existing tokens.
- **Supporting Tests:**
  - `tests/test_roles.py::test_registration_cannot_self_assign_admin`
  - `tests/test_roles.py::test_viewer_cannot_access_admin_endpoints`
  - `tests/test_roles.py::test_admin_cannot_deactivate_self`
  - `tests/test_roles.py::test_admin_cannot_deactivate_last_admin`
  - `tests/test_roles.py::test_admin_cannot_demote_last_admin`
  - `tests/test_roles.py::test_deactivated_user_cannot_login_or_authenticate`

---

### T4. Malicious File Upload and Path Traversal
- **Threat:** An attacker uploads executable binaries, oversized files to exhaust server disk space, or utilizes `../../` filename manipulation to overwrite arbitrary system files.
- **Potential Impact:** Remote code execution, server denial of service, or arbitrary file overwrite.
- **Mitigations Implemented:**
  - MIME-type whitelisting (`ALLOWED_CONTENT_TYPES`: `application/pdf`, `text/plain`, `image/png`, `image/jpeg`).
  - Strict upload size validation (`MAX_FILE_SIZE = 10 MB`), returning HTTP 413 Content Too Large.
  - Empty files and blank titles are rejected with HTTP 400 Bad Request.
  - Filenames are sanitized using `Path(filename).name` and prefixed with a UUID hex string (`{uuid4().hex}_{original_name}`).
  - File downloads validate that the target path is strictly contained within the resolved `storage/` directory using `storage_path.is_relative_to(STORAGE_DIR.resolve())`.
- **Supporting Tests:**
  - `tests/test_document_lifecycle.py::test_upload_validation_unsupported_mimetype`
  - `tests/test_document_lifecycle.py::test_upload_validation_empty_file`
  - `tests/test_document_lifecycle.py::test_upload_validation_blank_title`
  - `tests/test_document_lifecycle.py::test_upload_validation_oversized_file`
  - `tests/test_document_lifecycle.py::test_upload_filename_traversal_prevented`

---

### T5. Unauthorized Permission Manipulation and Document Deletion
- **Threat:** A non-owner or a user granted edit permissions attempts to delete a document, share it with unauthorized third parties, or revoke permissions.
- **Potential Impact:** Unauthorized permission grants or permanent data loss.
- **Mitigations Implemented:**
  - Sharing (`POST /documents/{id}/share`) and revocation (`DELETE /documents/{id}/share/{user_id}`) strictly enforce document ownership.
  - Self-sharing is rejected with HTTP 400 Bad Request. Duplicate shares return HTTP 409 Conflict.
  - Document deletion (`DELETE /documents/{id}`) is strictly owner-exclusive. Users with `can_edit=True` receive HTTP 403 Forbidden.
  - Deletion safely cascades permission removal, unlinks physical storage files, and permanently preserves historical audit records.
  - Database schema decouples `audit_events.document_id` from hard cascading foreign keys, preventing database integrity violations or audit trail destruction upon document deletion.
- **Supporting Tests:**
  - `tests/test_documents.py::test_non_owner_cannot_share_document`
  - `tests/test_documents.py::test_non_owner_cannot_revoke_access`
  - `tests/test_documents.py::test_duplicate_share_is_rejected`
  - `tests/test_document_lifecycle.py::test_user_with_edit_permission_cannot_delete_document`
  - `tests/test_document_lifecycle.py::test_owner_can_delete_document_and_cleans_up_storage`
  - `tests/test_document_lifecycle.py::test_document_deletion_with_foreign_keys_preserves_audit_trail`

---

### T6. Audit Log Tampering, Deletion, and History Manipulation
- **Threat:** A malicious user or rogue insider alters audit log details, deletes incriminating events, or swaps event records to cover their tracks.
- **Potential Impact:** Repudiation, loss of accountability, and inability to conduct forensic investigations.
- **Mitigations Implemented:**
  - Every security-relevant event (upload, share, revoke, download, update, delete, denied attempts) creates an immutable audit record.
  - Each audit event computes a deterministic SHA-256 hash across canonical JSON representations of `actor_id`, `action`, `document_id`, `details`, `created_at` (canonical UTC ISO 8601), and `prev_hash`.
  - First event links to genesis hash (`0` * 64). Subsequent events link strictly to the previous event's hash.
  - Audit verification (`verify_audit_chain`) recalculates the hash chain from genesis to head, detecting altered event details, forged hashes, deleted events, or reordered records.
  - Document owners can verify their document's audit chain (`GET /documents/{id}/audit/verify`).
  - Administrators can verify platform-wide audit chain integrity (`GET /admin/audit/verify`).
  - Alembic migration (`0002_add_updated_at_and_audit_hash_chain`) deterministically backfills existing historical audit records chronologically without corrupting chain continuity.
- **Supporting Tests:**
  - `tests/test_audit_chain.py::test_audit_chain_valid_sequence`
  - `tests/test_audit_chain.py::test_audit_chain_detects_altered_event_fields`
  - `tests/test_audit_chain.py::test_audit_chain_detects_altered_hash`
  - `tests/test_audit_chain.py::test_audit_chain_detects_deleted_event`
  - `tests/test_audit_chain.py::test_audit_chain_detects_reordered_events`
  - `tests/test_audit_chain.py::test_owner_can_verify_document_audit_chain`
  - `tests/test_audit_chain.py::test_non_owner_cannot_verify_document_audit_chain`
  - `tests/test_roles.py::test_admin_can_verify_audit_chain`
  - `tests/test_migrations.py::test_alembic_migrations_lifecycle`

---

### T7. Secret Disclosure and Credential Leakage
- **Threat:** Database credentials, JWT signing keys, or user password hashes are leaked via API responses, error messages, or logs.
- **Potential Impact:** Account compromise, total database compromise, or token forgery.
- **Mitigations Implemented:**
  - Passwords are encrypted with Argon2id; password hashes are excluded from `UserResponse` schemas.
  - Storage file paths are excluded from `DocumentResponse` schemas.
  - JWT signing secrets are loaded strictly from environment variables or `.env`.
  - Database health check (`/health/db`) catches database exceptions and logs only the exception type, preventing raw connection URLs with credentials from leaking into server logs or API responses.
  - Test suite uses HMAC secret keys meeting the RFC 7518 recommendation (>= 32 bytes), avoiding weak HMAC warnings.
  - `.gitignore` explicitly excludes `.env`, storage files, coverage reports, and caches.
- **Supporting Tests:**
  - `tests/test_auth.py::test_me_endpoint_token_validation`
  - `tests/test_models_and_schemas.py::test_document_response_backward_compatibility`
  - `tests/test_roles.py::test_admin_can_view_system_audit_metadata` (verifies passwords/tokens absent)

---

### T8. Denial of Service and Resource Exhaustion
- **Threat:** An attacker transmits massive queries, unpaginated listing requests, or oversized uploads to exhaust database and CPU resources.
- **Potential Impact:** Application degradation or complete service unavailability.
- **Mitigations Implemented:**
  - Maximum upload size restricted to 10 MB.
  - Search and listing endpoints enforce maximum limit constraints (`limit <= 100`, `limit <= 500`).
  - Database connections utilize connection pooling with pre-ping validation (`pool_pre_ping=True`).
- **Supporting Tests:**
  - `tests/test_document_lifecycle.py::test_upload_validation_oversized_file`
  - `tests/test_search.py::test_search_pagination`

---

## 5. Summary of Automated Security Test Suite

The automated test suite verifies all security controls across **74 test cases** with **zero warnings and zero failures**:

| Test Suite | Tests | Key Security Controls Verified |
| :--- | :---: | :--- |
| `tests/test_audit_chain.py` | 9 | Cryptographic SHA-256 hash chaining, tamper detection (altered fields, altered hashes, deleted records, reordered records), owner vs. non-owner verification |
| `tests/test_auth.py` | 4 | Password complexity, duplicate email rejection, invalid/inactive user login prevention, JWT expiry, HMAC signature tampering (32+ byte keys) |
| `tests/test_document_lifecycle.py` | 17 | Upload size limit (HTTP 413), MIME-type whitelisting, empty file rejection, path traversal protection, owner vs. editor vs. outsider updates, owner-only deletion, storage unlinking, FK-safe deletion |
| `tests/test_documents.py` | 14 | Sharing authorization, immediate revocation, download permissions, duplicate share rejection, audit event recording on upload/share/revoke, owner audit log access |
| `tests/test_migrations.py` | 1 | Alembic versioned migration lifecycle, legacy schema upgrade, additive column verification (`updated_at`, `prev_hash`, `hash`), historical audit record backfill and chain verification |
| `tests/test_models_and_schemas.py` | 7 | Additive model fields, Pydantic schema validation for roles and updates, backward compatibility of response serialization |
| `tests/test_roles.py` | 13 | Registration privilege escalation prevention, viewer restriction on admin endpoints, admin user governance, inactive user login denial, self-deactivation guard, last admin protection, bootstrap utility |
| `tests/test_search.py` | 9 | Keyword match, category filter, owner filter, date range filter, pagination, strict authorization isolation (outsiders receive 0 results) |
| **Total** | **74** | **100% Passed, 0 Failures, 0 Warnings** |

---

## 6. Residual Risks and Operational Safeguards

1. **Privileged Database Administrator Limitation:**
   - *Risk:* The SHA-256 hash chain provides tamper evidence against application-layer modifications and standard SQL injections. However, a privileged database administrator or compromised superuser with direct table write access could modify historical records and recalculate all subsequent hashes.
   - *Operational Safeguard:* In high-assurance production environments, stream audit events to immutable write-once (WORM) storage (e.g., AWS S3 Object Lock), remote append-only Syslog, or a dedicated SIEM system.
2. **Virus and Malware Scanning:**
   - *Risk:* The application validates MIME types and file extensions, but does not execute deep heuristic antivirus scanning on uploaded files.
   - *Operational Safeguard:* In enterprise deployments handling untrusted public uploads, integrate an asynchronous virus scanning pipeline (e.g., ClamAV daemon) before making files available for download.
3. **Application Layer Rate Limiting:**
   - *Risk:* Login attempts and search queries are fast, but absence of IP-based rate limiting leaves the application vulnerable to sustained brute-force or volumetric denial of service.
   - *Operational Safeguard:* Deploy a reverse proxy (e.g., NGINX, Cloudflare) with rate limiting rules configured on `/auth/login` and `/documents/search`.
4. **Live Deployment Synchronization:**
   - *Risk:* The public instance currently deployed on Render reflects an earlier commit and requires the latest reviewed code to be pushed and migrations to be executed.
   - *Operational Safeguard:* Execute the recommended Alembic migration (`alembic upgrade head`) immediately upon deploying the latest commit to Render.
