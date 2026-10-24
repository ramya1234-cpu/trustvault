# TrustVault — AI Usage and Prompt Log

This document records how AI tools were used during the development of TrustVault. AI-generated suggestions were reviewed and checked against the project implementation. Features and tests are not considered complete until verified.

## Entry 1 — October 20, 2026
**Task:** Initial project setup

**Prompt used:**
> Help me structure a secure document-sharing application using Python, FastAPI, and PostgreSQL. Suggest a maintainable project structure and explain the purpose of each component.

**AI assistance:** Helped plan the backend structure, configuration, database connection, authentication components, and initial documentation files.

**Verification:** Project files were created, and the initial setup was committed to GitHub.

**Commit:** `719c5cd` — Set up TrustVault project.

## Entry 2 — October 21, 2026
**Task:** Document upload and listing

**Prompt used:**
> Help implement authenticated document upload and listing in FastAPI. Include file type validation, a file size limit, safe storage filenames, and database persistence.

**AI assistance:** Helped develop the document upload and listing endpoints and basic upload validation.

**Verification:** Python compilation and code-format checks were run. Additional upload and authorization tests remain necessary.

**Commit:** `4c76f35` — Implement document upload and listing.

## Entry 3 — October 21, 2026
**Task:** Authorization and document sharing

**Prompt used:**
> Review a FastAPI document-sharing implementation. Ensure only the document owner can grant access, validate the recipient, and prevent duplicate permissions. Identify authorization risks.

**AI assistance:** Helped implement owner checks, recipient validation, duplicate-permission handling, and permission validation.

**Verification:** The code was reviewed and basic validation checks were run. Complete automated authorization testing is still pending.

**Commit:** `cc9cbb5` — Add document sharing and access revocation.

## Entry 4 — October 21, 2026
**Task:** Authorization testing plan

**Prompt used:**
> Design automated security tests for a document-sharing API. Test that non-owners cannot share or revoke access, recipients can access only documents they are authorized to read, and revoked access no longer works.

**AI assistance:** Helped identify important authorization test scenarios and expected HTTP responses.

**Verification:** Test scenarios have been identified. Automated tests must be implemented and run before these behaviors can be considered verified.

**Commit:** Pending.

## Entry 5 — October 21, 2026
**Task:** Audit trail and security review

**Prompt used:**
> Review a secure document-sharing application for audit logging requirements. Recommend how to record sharing, revocation, access-denied events, and how to protect audit records from unauthorized modification.

**AI assistance:** Helped identify audit events and security controls that should be implemented.

**Verification:** Audit logging and its security tests still need implementation and verification.

**Commit:** Pending.

## Entry 6 — October 24, 2026
**Task:** Final end-to-end completion, security hardening, database migrations, and testing

**Prompt used:**
> Act as a senior Python backend engineer, application security reviewer, QA engineer, and deployment engineer. Complete all remaining work in my existing TrustVault project. Fix remaining warnings, complete security review and fixes, implement PostgreSQL Alembic migrations with historical backfill, verify live deployment status, run tests, and prepare submission readiness.

**AI assistance:**
- Conducted full project inspection and working-tree review.
- Fixed Starlette deprecation warning by installing `httpx2` and updating dependencies.
- Replaced deprecated `HTTP_413_REQUEST_ENTITY_TOO_LARGE` with `HTTP_413_CONTENT_TOO_LARGE`.
- Replaced short JWT HMAC test key with RFC 7518-compliant test key of at least 32 bytes (`wrong_test_secret_key_at_least_32_bytes_long_12345`), resolving the InsecureKeyLengthWarning.
- Replaced generic `object` types for timestamps with `datetime` in Pydantic schemas.
- Hardened database health check exception logging in `app/main.py` to prevent potential leakage of database connection credentials in error logs.
- Resolved database foreign key constraint hazard: decoupled `audit_events.document_id` from hard foreign key constraint so that document deletion preserves the permanent audit trail without raising foreign key violations when foreign keys are enforced.
- Added regression test `test_document_deletion_with_foreign_keys_preserves_audit_trail` to verify document deletion and audit chain preservation with foreign keys enabled.
- Implemented versioned Alembic migrations (`0001_initial_schema`, `0002_add_updated_at_and_audit_hash_chain`) with safe column additions and deterministic chronological backfill of historical audit events.
- Created `tests/test_migrations.py` to test the full migration upgrade/downgrade lifecycle and audit chain verification against a legacy database.
- Created `.env.example` with safe placeholder configuration.
- Converted `requirements.txt` to UTF-8 encoding.
- Inspected live deployment on Render and verified that live endpoints are up (`/health` and `/health/db`), while confirming that live code currently reflects an earlier version and requires deployment of the latest commits and migrations.

**Verification Results:**
- Automated test command: `.\.venv\Scripts\python.exe -m pytest -v`
- Result: **74 passed, 0 failures, 0 warnings** in 8.70s.
- Python compilation check: `python -m compileall app tests alembic` passed with 0 errors.
- Whitespace validation: `git diff --check` passed with 0 warnings.
- Live deployment check: `GET https://trustvault-o3fn.onrender.com/health` returned `{"status": "ok"}`; `GET https://trustvault-o3fn.onrender.com/health/db` returned `{"database": "connected"}`.

**Commit:** `c371246` — Complete TrustVault security hardening and tests.

**Limitations:**
- Cryptographic hash chaining provides tamper evidence against application and record-level tampering, but cannot prevent a privileged database administrator or compromised database superuser with direct SQL access from modifying table contents and recalculating downstream hashes.
- The latest local features and migrations have been verified locally; they will become active on the live Render deployment once the reviewed Git commits are pushed and `alembic upgrade head` is executed.