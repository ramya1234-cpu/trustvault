from datetime import datetime, timedelta, timezone
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_db
from app.config import settings
from app.main import app
from app import documents as documents_module
from app.models import Base, User
from app.security import ALGORITHM, hash_password


@pytest.fixture
def auth_test_setup(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(documents_module, "STORAGE_DIR", tmp_path)
    monkeypatch.setattr("app.main.engine", engine)
    monkeypatch.setattr("app.database.engine", engine)

    db = TestingSessionLocal()
    user = User(
        email="test_auth_user@example.com",
        full_name="Auth User",
        password_hash=hash_password("ValidPassword123!"),
        role="viewer",
        is_active=True,
    )
    inactive_user = User(
        email="inactive_user@example.com",
        full_name="Inactive User",
        password_hash=hash_password("ValidPassword123!"),
        role="viewer",
        is_active=False,
    )
    db.add_all([user, inactive_user])
    db.commit()
    user_id = user.id
    inactive_id = inactive_user.id
    db.close()

    def override_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db

    try:
        with TestClient(app) as client:
            yield client, user_id, inactive_id, TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_registration_validation(auth_test_setup):
    client, _, _, _ = auth_test_setup

    # Password too short (<12 characters)
    resp1 = client.post(
        "/auth/register",
        json={
            "email": "valid@example.com",
            "full_name": "Valid User",
            "password": "short",
        },
    )
    assert resp1.status_code == 422

    # Invalid email format (too short)
    resp2 = client.post(
        "/auth/register",
        json={
            "email": "a@b",
            "full_name": "Valid User",
            "password": "ValidPassword123!",
        },
    )
    assert resp2.status_code == 422

    # Successful registration
    resp3 = client.post(
        "/auth/register",
        json={
            "email": "newuser@example.com",
            "full_name": "New User",
            "password": "ValidPassword123!",
        },
    )
    assert resp3.status_code == 201
    assert resp3.json()["email"] == "newuser@example.com"
    assert resp3.json()["role"] == "viewer"
    assert resp3.json()["is_active"] is True


def test_duplicate_email_registration_conflict(auth_test_setup):
    client, _, _, _ = auth_test_setup

    resp = client.post(
        "/auth/register",
        json={
            "email": "test_auth_user@example.com",
            "full_name": "Duplicate User",
            "password": "ValidPassword123!",
        },
    )
    assert resp.status_code == 409
    assert "already exists" in resp.json()["detail"]


def test_login_success_and_failure(auth_test_setup):
    client, _, _, _ = auth_test_setup

    # Valid credentials
    resp1 = client.post(
        "/auth/login",
        json={
            "email": "test_auth_user@example.com",
            "password": "ValidPassword123!",
        },
    )
    assert resp1.status_code == 200
    token = resp1.json()["access_token"]
    assert token is not None

    # Invalid password
    resp2 = client.post(
        "/auth/login",
        json={
            "email": "test_auth_user@example.com",
            "password": "WrongPassword123!",
        },
    )
    assert resp2.status_code == 401
    assert "Incorrect email or password" in resp2.json()["detail"]

    # Nonexistent user
    resp3 = client.post(
        "/auth/login",
        json={
            "email": "unknown@example.com",
            "password": "ValidPassword123!",
        },
    )
    assert resp3.status_code == 401

    # Inactive user login
    resp4 = client.post(
        "/auth/login",
        json={
            "email": "inactive_user@example.com",
            "password": "ValidPassword123!",
        },
    )
    assert resp4.status_code == 401


def test_me_endpoint_token_validation(auth_test_setup):
    client, user_id, inactive_id, _ = auth_test_setup

    # 1. Missing Authorization header
    resp1 = client.get("/auth/me")
    assert resp1.status_code == 401
    assert "Authentication required" in resp1.json()["detail"]

    # 2. Malformed token
    resp2 = client.get("/auth/me", headers={"Authorization": "Bearer not-a-valid-jwt"})
    assert resp2.status_code == 401
    assert "Invalid or expired token" in resp2.json()["detail"]

    # 3. Expired token
    expired_payload = {
        "sub": str(user_id),
        "role": "viewer",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=10),
    }
    expired_token = jwt.encode(expired_payload, settings.jwt_secret, algorithm=ALGORITHM)
    resp3 = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp3.status_code == 401
    assert "Invalid or expired token" in resp3.json()["detail"]

    # 4. Tampered token (signed with wrong secret of at least 32 bytes)
    tampered_token = jwt.encode(
        {"sub": str(user_id), "role": "administrator", "exp": datetime.now(timezone.utc) + timedelta(minutes=30)},
        "wrong_test_secret_key_at_least_32_bytes_long_12345",
        algorithm=ALGORITHM,
    )
    resp4 = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp4.status_code == 401

    # 5. Token for inactive user
    inactive_token = jwt.encode(
        {"sub": str(inactive_id), "role": "viewer", "exp": datetime.now(timezone.utc) + timedelta(minutes=30)},
        settings.jwt_secret,
        algorithm=ALGORITHM,
    )
    resp5 = client.get("/auth/me", headers={"Authorization": f"Bearer {inactive_token}"})
    assert resp5.status_code == 401
    assert "Invalid or inactive user" in resp5.json()["detail"]

    # 6. Valid token
    valid_token = jwt.encode(
        {"sub": str(user_id), "role": "viewer", "exp": datetime.now(timezone.utc) + timedelta(minutes=30)},
        settings.jwt_secret,
        algorithm=ALGORITHM,
    )
    resp6 = client.get("/auth/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert resp6.status_code == 200
    assert resp6.json()["email"] == "test_auth_user@example.com"
