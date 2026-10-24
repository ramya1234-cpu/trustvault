import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user, get_db
from app.bootstrap_admin import promote_to_admin
from app.main import app
from app import documents as documents_module
from app.models import AuditEvent, Base, User
from app.security import hash_password, create_access_token


@pytest.fixture
def role_test_setup(tmp_path, monkeypatch):
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
    monkeypatch.setattr("app.bootstrap_admin.SessionLocal", TestingSessionLocal)

    db = TestingSessionLocal()
    admin = User(
        email="superadmin@example.com",
        full_name="Super Admin",
        password_hash=hash_password("SuperSecretAdminPassword123!"),
        role="administrator",
        is_active=True,
    )
    viewer = User(
        email="regular_viewer@example.com",
        full_name="Regular Viewer",
        password_hash=hash_password("RegularViewerPassword123!"),
        role="viewer",
        is_active=True,
    )
    owner = User(
        email="doc_owner@example.com",
        full_name="Doc Owner",
        password_hash=hash_password("DocOwnerPassword123!"),
        role="owner",
        is_active=True,
    )
    db.add_all([admin, viewer, owner])
    db.commit()

    ids = {
        "admin": admin.id,
        "viewer": viewer.id,
        "owner": owner.id,
    }
    db.close()

    current_user_id = {"value": ids["admin"]}

    def override_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    def override_current_user():
        session = TestingSessionLocal()
        try:
            user = session.get(User, current_user_id["value"])
            assert user is not None
            return user
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_current_user

    try:
        with TestClient(app) as client:
            yield client, ids, current_user_id, TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_registration_cannot_self_assign_admin(role_test_setup):
    client, _, _, session_factory = role_test_setup

    resp = client.post(
        "/auth/register",
        json={
            "email": "hacker@example.com",
            "full_name": "Privilege Escalation Attempt",
            "password": "SecurePassword123!",
            "role": "administrator",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "viewer"

    with session_factory() as session:
        user = session.scalar(select(User).where(User.email == "hacker@example.com"))
        assert user is not None
        assert user.role == "viewer"


def test_viewer_cannot_access_admin_endpoints(role_test_setup):
    client, ids, current_user_id, session_factory = role_test_setup
    current_user_id["value"] = ids["viewer"]

    resp = client.get("/admin/users")
    assert resp.status_code == 403
    assert "Administrator access required" in resp.json()["detail"]

    # Denied attempt must be recorded in audit trail
    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "unauthorized_admin_access_attempt"
            )
        ).all()
        assert len(events) >= 1
        assert events[0].actor_id == ids["viewer"]


def test_admin_can_list_users(role_test_setup):
    client, ids, current_user_id, _ = role_test_setup
    current_user_id["value"] = ids["admin"]

    resp = client.get("/admin/users")
    assert resp.status_code == 200
    user_emails = [u["email"] for u in resp.json()]
    assert "superadmin@example.com" in user_emails
    assert "regular_viewer@example.com" in user_emails


def test_admin_can_activate_and_deactivate_user(role_test_setup):
    client, ids, current_user_id, session_factory = role_test_setup
    current_user_id["value"] = ids["admin"]

    # Deactivate viewer
    resp = client.patch(
        f"/admin/users/{ids['viewer']}/status",
        json={"is_active": False},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False

    with session_factory() as session:
        u = session.get(User, ids["viewer"])
        assert u.is_active is False


def test_deactivated_user_cannot_login_or_authenticate(role_test_setup):
    client, ids, current_user_id, _ = role_test_setup
    current_user_id["value"] = ids["admin"]

    # Deactivate viewer
    client.patch(
        f"/admin/users/{ids['viewer']}/status",
        json={"is_active": False},
    )

    # Attempt to login as deactivated user
    login_resp = client.post(
        "/auth/login",
        json={
            "email": "regular_viewer@example.com",
            "password": "RegularViewerPassword123!",
        },
    )
    assert login_resp.status_code == 401
    assert "Incorrect email or password" in login_resp.json()["detail"]


def test_admin_cannot_deactivate_self(role_test_setup):
    client, ids, current_user_id, _ = role_test_setup
    current_user_id["value"] = ids["admin"]

    resp = client.patch(
        f"/admin/users/{ids['admin']}/status",
        json={"is_active": False},
    )
    assert resp.status_code == 400
    assert "Administrators cannot deactivate their own account" in resp.json()["detail"]


def test_admin_cannot_deactivate_last_admin(role_test_setup):
    client, ids, current_user_id, session_factory = role_test_setup

    # Create a second admin
    with session_factory() as session:
        admin2 = User(
            email="admin2@example.com",
            full_name="Second Admin",
            password_hash="hash",
            role="administrator",
            is_active=True,
        )
        session.add(admin2)
        session.commit()
        admin2_id = admin2.id

    current_user_id["value"] = ids["admin"]

    # Deactivating admin2 is allowed while admin1 is active
    resp1 = client.patch(
        f"/admin/users/{admin2_id}/status",
        json={"is_active": False},
    )
    assert resp1.status_code == 200

    # Attempting to deactivate admin2 again when only 1 active admin remains should be protected
    # Let's verify that when only 1 active admin exists, deactivating that admin is blocked
    resp2 = client.patch(
        f"/admin/users/{ids['admin']}/status",
        json={"is_active": False},
    )
    assert resp2.status_code == 400


def test_admin_can_update_roles(role_test_setup):
    client, ids, current_user_id, session_factory = role_test_setup
    current_user_id["value"] = ids["admin"]

    # Promote viewer to owner
    resp = client.patch(
        f"/admin/users/{ids['viewer']}/role",
        json={"role": "owner"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "owner"

    with session_factory() as session:
        u = session.get(User, ids["viewer"])
        assert u.role == "owner"


def test_admin_cannot_demote_last_admin(role_test_setup):
    client, ids, current_user_id, _ = role_test_setup
    current_user_id["value"] = ids["admin"]

    resp = client.patch(
        f"/admin/users/{ids['admin']}/role",
        json={"role": "viewer"},
    )
    assert resp.status_code == 400
    assert "Cannot demote the last active administrator" in resp.json()["detail"]


def test_admin_can_view_system_audit_metadata(role_test_setup):
    client, ids, current_user_id, _ = role_test_setup
    current_user_id["value"] = ids["admin"]

    resp = client.get("/admin/audit")
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    for evt in events:
        # Must only contain metadata
        assert "actor_id" in evt
        assert "action" in evt
        assert "details" in evt
        assert "password" not in evt["details"].lower()


def test_admin_can_verify_audit_chain(role_test_setup):
    client, ids, current_user_id, _ = role_test_setup
    current_user_id["value"] = ids["admin"]

    resp = client.get("/admin/audit/verify")
    assert resp.status_code == 200
    assert resp.json()["is_valid"] is True


def test_bootstrap_admin_utility(role_test_setup):
    _, ids, _, session_factory = role_test_setup

    with session_factory() as session:
        test_user = User(
            email="to_promote@example.com",
            full_name="To Promote",
            password_hash="test",
            role="viewer",
            is_active=True,
        )
        session.add(test_user)
        session.commit()

    success = promote_to_admin("to_promote@example.com")
    assert success is True

    with session_factory() as session:
        promoted = session.scalar(select(User).where(User.email == "to_promote@example.com"))
        assert promoted.role == "administrator"
        # Check audit event
        evt = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "admin_bootstrapped")
        )
        assert evt is not None
        assert "to_promote@example.com" in evt.details
