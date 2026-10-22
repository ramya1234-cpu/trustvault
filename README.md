\# TrustVault — Secure Document Sharing with Audit Trail



TrustVault is a backend application for securely uploading, listing, and sharing documents with authenticated users. It includes document-level access permissions, access revocation, and audit-event logging.



\## Features



\- User registration and login

\- JWT-based authentication

\- Password hashing using Argon2

\- Document upload with file size and file type restrictions

\- Document listing based on ownership and read permissions

\- Owner-controlled document sharing

\- Access revocation

\- Owner-only audit-log endpoint

\- PostgreSQL database integration

\- Automated security and authorization tests



\## Technology Stack



\- \*\*Backend:\*\* Python, FastAPI

\- \*\*Database:\*\* PostgreSQL

\- \*\*ORM:\*\* SQLAlchemy

\- \*\*Authentication:\*\* JWT

\- \*\*Password Hashing:\*\* Argon2

\- \*\*Testing:\*\* pytest

\- \*\*Containerization:\*\* Docker and Docker Compose



\## Project Structure



```text

trustvault/

├── app/

│   ├── auth.py

│   ├── config.py

│   ├── database.py

│   ├── documents.py

│   ├── init\_db.py

│   ├── main.py

│   ├── models.py

│   ├── schemas.py

│   └── security.py

├── docs/

├── storage/

├── tests/

│   └── test\_documents.py

├── .env

├── .gitignore

├── compose.yaml

├── requirements.txt

├── THREATS.md

└── README.md

```



\## Prerequisites



\- Python 3.12 or compatible version

\- Docker Desktop with its engine running

\- Git



\## Local Setup



\### 1. Clone the repository



```bash

git clone https://github.com/ramya1234-cpu/trustvault.git

cd trustvault

```



\### 2. Create and activate a virtual environment



Windows PowerShell:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



\### 3. Install dependencies



```powershell

python -m pip install -r requirements.txt

```



\### 4. Configure environment variables



Create a local `.env` file using the variable names expected by `app/config.py`.



Configure:

\- `DATABASE\_URL` — PostgreSQL connection string

\- `JWT\_SECRET` — a strong, randomly generated secret



Use the exact environment variable names and database settings supported by the project configuration. Never commit `.env` or expose secrets in logs, screenshots, or source control.



\### 5. Start PostgreSQL



```powershell

docker compose up -d db

docker compose ps

```



Wait until the database container reports a healthy status.



\### 6. Start the API



```powershell

python -m uvicorn app.main:app --reload

```



The API should be available at:



\- \*\*Swagger UI:\*\* http://127.0.0.1:8000/docs

\- \*\*Health check:\*\* http://127.0.0.1:8000/health

\- \*\*Database health check:\*\* http://127.0.0.1:8000/health/db



\## Testing



Run the automated test suite:



```powershell

python -m pytest -q

```



The current document test suite has passed \*\*11 tests\*\* in the local development environment.



These tests cover document-sharing authorization, access revocation, duplicate sharing, nonexistent documents, audit-event creation, and audit-log access restrictions.



\## Security Considerations



\- Authenticated endpoints should validate the user's identity.

\- Document access must be checked server-side for every protected operation.

\- Only document owners should be allowed to grant or revoke access.

\- Revoked permissions must no longer authorize document access.

\- Audit events should be protected from unauthorized access and modification.

\- Secrets must be stored outside source control.

\- Production deployment requires appropriate database access controls, secure secret management, HTTPS, and operational monitoring.



Review `THREATS.md` for the project's documented security risks and mitigations.



\## Project Status



The backend implementation and the current automated test suite are available in this repository. Local API and database health checks have been performed.



Production deployment and a complete production security assessment are not claimed by this README.



\## License



Add the applicable license before distributing this project publicly.



