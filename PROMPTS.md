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

## Errors, fixes, and limitations

- Python compilation completed successfully using `python -m compileall app`.
- `git diff --check` completed without reporting whitespace errors.
- Pydantic validation rejected `user_id=0` after positive-ID validation was added.
- Running `python -m pytest -v` reported that zero tests were collected. Automated security tests therefore remain a required task.
- These checks do not prove that document-sharing or revocation behavior is secure.
- AI suggestions were used as development assistance; implementation and test results must be verified independently.

## Remaining work

- Implement and run automated authorization tests.
- Enforce permissions on actual document-reading or download endpoints.
- Implement and test protected audit logging.
- Complete search and administrative activity features required by the challenge.
- Complete README.md and THREATS.md.
- Deploy the application and verify the live instance.
- Update this log with actual prompts, errors, fixes, and commit links as work continues.
