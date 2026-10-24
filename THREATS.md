\# TrustVault — Threat Model



\## 1. Overview



TrustVault is a secure document-sharing backend built with Python, FastAPI, SQLAlchemy, and PostgreSQL. It supports user authentication, document upload, permission-based sharing, access revocation, and audit-event logging.



This document identifies key security threats, existing controls, and recommended mitigations.



\## 2. Assets to Protect



\- User credentials and password hashes

\- JWT access tokens and signing secrets

\- Uploaded documents and their contents

\- Document ownership and permission records

\- Audit events and security-relevant metadata

\- Database credentials and configuration secrets



\## 3. Trust Boundaries



\- \*\*Client to API:\*\* All incoming requests are untrusted.

\- \*\*Authentication boundary:\*\* Protected endpoints must validate the user's identity and token.

\- \*\*Authorization boundary:\*\* The backend must enforce document ownership and permissions for each protected operation.

\- \*\*API to database:\*\* Database access must use secure configuration and appropriate privileges.

\- \*\*API to file storage:\*\* Uploaded files must be stored safely and must not be accessible through unauthorized paths.

\- \*\*Audit boundary:\*\* Audit records must be protected against unauthorized reading, modification, and deletion.



\## 4. Threats and Mitigations



\### T1. Unauthorized Document Access



\*\*Threat:\*\* A user attempts to access a document owned by another user without permission.



\*\*Potential impact:\*\* Confidential documents may be exposed.



\*\*Existing controls:\*\*

\- Document listing is restricted to owned documents and documents with read permission.

\- Document-sharing operations enforce owner-only access.

\- Automated tests cover important authorization scenarios.



\*\*Recommended mitigations:\*\*

\- Enforce authorization on every document read, download, update, share, and delete endpoint.

\- Deny access by default when ownership or permission checks fail.

\- Add negative tests for every protected endpoint.



\### T2. Access After Revocation



\*\*Threat:\*\* A previously authorized recipient attempts to access a document after their permission is revoked.



\*\*Potential impact:\*\* Continued unauthorized disclosure of confidential information.



\*\*Existing controls:\*\*

\- Revocation removes the recipient's permission record.

\- An audit event is created for revocation.

\- Automated tests verify that a revoked recipient no longer sees the document in the listing endpoint.



\*\*Recommended mitigations:\*\*

\- Recheck current permissions on every protected request.

\- Avoid relying on stale permission data or long-lived authorization caches.

\- Test access after revocation against every applicable document endpoint.



\### T3. Credential Theft and Token Abuse



\*\*Threat:\*\* An attacker obtains a user's password or JWT access token.



\*\*Potential impact:\*\* The attacker may impersonate the user until the credential or token is invalidated or expires.



\*\*Existing controls:\*\*

\- Passwords are hashed using Argon2.

\- JWT-based authentication is implemented.

\- Tokens have a configured expiration time.



\*\*Recommended mitigations:\*\*

\- Store signing secrets outside source control.

\- Use HTTPS in deployed environments.

\- Validate token signature, expiration, and relevant claims.

\- Apply login rate limiting and account-abuse protections.

\- Define a token-revocation strategy if immediate logout or credential invalidation is required.



\### T4. Malicious File Upload



\*\*Threat:\*\* A user uploads an oversized, malformed, or disguised file.



\*\*Potential impact:\*\* Resource exhaustion, unsafe file handling, or exposure of malicious content.



\*\*Existing controls:\*\*

\- The upload endpoint restricts accepted MIME types.

\- A maximum file size is enforced.

\- Empty files and blank titles are rejected.

\- Randomized storage filenames are used.



\*\*Recommended mitigations:\*\*

\- Verify file signatures rather than trusting client-supplied MIME types alone.

\- Store uploads outside publicly served directories.

\- Apply appropriate filesystem permissions and resource limits.

\- Consider malware scanning and safe download headers before supporting broader file use.



\### T5. Unauthorized Permission Changes



\*\*Threat:\*\* A non-owner attempts to grant or revoke access to another user's document.



\*\*Potential impact:\*\* Unauthorized disclosure or denial of legitimate access.



\*\*Existing controls:\*\*

\- Sharing and revocation endpoints enforce document-owner authorization.

\- Automated tests cover non-owner sharing and revocation attempts.

\- Duplicate sharing and nonexistent-document cases are tested.



\*\*Recommended mitigations:\*\*

\- Apply server-side ownership checks to every permission-management operation.

\- Validate recipient identity and requested permission values.

\- Test self-sharing, inactive recipients, and concurrent permission changes.



\### T6. Audit-Log Exposure or Tampering



\*\*Threat:\*\* An unauthorized user reads audit events, or an attacker modifies or deletes audit records.



\*\*Potential impact:\*\* Disclosure of security-sensitive metadata or loss of accountability.



\*\*Existing controls:\*\*

\- An audit-log endpoint is implemented with owner-only access checks.

\- Upload, share, and revoke operations create audit events.

\- Automated tests verify audit-event creation and owner-only audit-log access.



\*\*Limitations:\*\*

\- Application-level authorization does not by itself make audit logs tamper-proof.

\- Protection against database administrators or compromised database credentials has not been independently established.



\*\*Recommended mitigations:\*\*

\- Restrict database privileges for audit records.

\- Consider append-only external logging or tamper-evident storage.

\- Record relevant security events consistently and monitor failures.

\- Avoid storing passwords, tokens, or unnecessary sensitive document contents in audit details.



\### T7. Database or Configuration Exposure



\*\*Threat:\*\* Database credentials, JWT secrets, or sensitive configuration are exposed.



\*\*Potential impact:\*\* Unauthorized database access, account impersonation, or data compromise.



\*\*Existing controls:\*\*

\- Environment-based configuration is used.

\- `.env` is intended to remain outside source control.



\*\*Recommended mitigations:\*\*

\- Verify that secrets are excluded from Git history and repository contents.

\- Use strong, unique secrets and rotate any exposed credentials.

\- Restrict database network access and database-user privileges.

\- Use managed secret storage and encrypted connections in production where appropriate.



\### T8. Denial of Service



\*\*Threat:\*\* An attacker sends excessive requests or repeated large uploads.



\*\*Potential impact:\*\* API unavailability, high resource usage, or database exhaustion.



\*\*Existing controls:\*\*

\- A maximum upload size is enforced.



\*\*Recommended mitigations:\*\*

\- Add request rate limiting and upload quotas.

\- Configure connection and request timeouts.

\- Apply database connection-pool limits and operational monitoring.

\- Consider limits on concurrent uploads and expensive operations.



\## 5. Security Testing



The current document test suite has passed 15 automated tests in the local development environment.



Covered scenarios include:

\- Non-owner sharing and revocation restrictions

\- Successful sharing and recipient visibility

\- Access removal after revocation

\- Duplicate sharing rejection

\- Nonexistent-document handling

\- Audit-event creation for upload, sharing, and revocation

\- Owner-only audit-log access



These results demonstrate the tested scenarios only; they do not constitute a complete security assessment.



\## 6. Residual Risks and Limitations



The following areas require further verification before production use:



\- File-signature validation and malicious-file handling

\- Authorization checks for any future download, edit, or delete endpoints

\- Audit-log tamper resistance beyond application-level controls

\- Rate limiting and abuse prevention

\- Production secret management, HTTPS, and database hardening

\- Production deployment and security testing



\## 7. Security Principles



TrustVault follows these intended principles:



1\. Deny access by default.

2\. Enforce authorization on the server.

3\. Apply least privilege.

4\. Revalidate permissions after revocation.

5\. Log security-relevant actions without exposing secrets.

6\. Keep secrets out of source control.

7\. Test both allowed and denied access paths.



\## 8. Conclusion



TrustVault implements foundational authentication, document-level authorization, access revocation, and audit-event logging. Additional hardening and verification are required before treating the application as production-ready or its audit logs as tamper-proof.



