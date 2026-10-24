import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user, get_db
from app.main import app
from app import documents as documents_module
from app.models import AuditEvent, Base, Document, User
from app.audit import GENESIS_HASH, compute_event_hash, record_audit_event, verify_audit_chain


@pytest.fixture
def audit_test_setup(tmp_path, monkeypatch):
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
    owner = User(
        email="chain_owner@example.com",
        full_name="Chain Owner",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    recipient = User(
        email="chain_recipient@example.com",
        full_name="Chain Recipient",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    outsider = User(
        email="chain_outsider@example.com",
        full_name="Chain Outsider",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    db.add_all([owner, recipient, outsider])
    db.commit()

    storage_dir = tmp_path
    file_path = storage_dir / "audit-test.txt"
    file_path.write_bytes(b"Audit trail content test")

    doc = Document(
        owner_id=owner.id,
        title="Audit Doc",
        category="Security",
        storage_path=str(file_path),
    )
    db.add(doc)
    db.commit()

    ids = {
        "owner": owner.id,
        "recipient": recipient.id,
        "outsider": outsider.id,
        "document": doc.id,
    }
    db.close()

    current_user_id = {"value": ids["owner"]}

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


def test_download_creates_audit_event(audit_test_setup):
    client, ids, current_user_id, session_factory = audit_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.get(f"/documents/{ids['document']}/download")
    assert resp.status_code == 200

    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.document_id == ids["document"],
                AuditEvent.action == "document_downloaded",
            )
        ).all()
        assert len(events) == 1
        assert events[0].actor_id == ids["owner"]
        assert events[0].prev_hash is not None
        assert events[0].hash is not None


def test_unauthorized_download_creates_denied_audit_event(audit_test_setup):
    client, ids, current_user_id, session_factory = audit_test_setup
    current_user_id["value"] = ids["outsider"]

    resp = client.get(f"/documents/{ids['document']}/download")
    assert resp.status_code == 403

    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.document_id == ids["document"],
                AuditEvent.action == "document_download_denied",
            )
        ).all()
        assert len(events) == 1
        assert events[0].actor_id == ids["outsider"]
        assert "Unauthorized download attempt" in events[0].details


def test_audit_chain_valid_sequence(audit_test_setup):
    client, ids, current_user_id, session_factory = audit_test_setup

    # 1. Share document
    client.post(
        f"/documents/{ids['document']}/share",
        json={"user_id": ids["recipient"], "can_read": True, "can_edit": False},
    )

    # 2. Recipient downloads document
    current_user_id["value"] = ids["recipient"]
    client.get(f"/documents/{ids['document']}/download")

    # 3. Owner revokes access
    current_user_id["value"] = ids["owner"]
    client.delete(f"/documents/{ids['document']}/share/{ids['recipient']}")

    with session_factory() as session:
        result = verify_audit_chain(session)
        assert result["is_valid"] is True
        assert result["total_events"] >= 3
        assert result["verified_events"] == result["total_events"]
        assert result["tampered_event_id"] is None


def test_audit_chain_detects_altered_event_fields(audit_test_setup):
    _, ids, _, session_factory = audit_test_setup

    with session_factory() as session:
        # Add 3 chained events
        record_audit_event(session, actor_id=ids["owner"], action="action_1", details="First")
        record_audit_event(session, actor_id=ids["owner"], action="action_2", details="Second")
        record_audit_event(session, actor_id=ids["owner"], action="action_3", details="Third")
        session.commit()

        # Chain must be valid initially
        assert verify_audit_chain(session)["is_valid"] is True

        # Maliciously tamper with the details of the 2nd event directly in the database
        second_event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "action_2")
        )
        assert second_event is not None
        second_event.details = "Forged Details by Attacker"
        session.commit()

        # Verification must now fail
        res = verify_audit_chain(session)
        assert res["is_valid"] is False
        assert res["tampered_event_id"] == second_event.id
        assert "Tampered event content detected" in res["message"]


def test_audit_chain_detects_altered_hash(audit_test_setup):
    _, ids, _, session_factory = audit_test_setup

    with session_factory() as session:
        record_audit_event(session, actor_id=ids["owner"], action="evt_1", details="One")
        record_audit_event(session, actor_id=ids["owner"], action="evt_2", details="Two")
        session.commit()

        # Maliciously tamper with hash
        first_event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "evt_1")
        )
        assert first_event is not None
        first_event.hash = "0" * 64
        session.commit()

        res = verify_audit_chain(session)
        assert res["is_valid"] is False
        assert res["tampered_event_id"] == first_event.id


def test_audit_chain_detects_deleted_event(audit_test_setup):
    _, ids, _, session_factory = audit_test_setup

    with session_factory() as session:
        record_audit_event(session, actor_id=ids["owner"], action="step_1", details="First")
        e2 = record_audit_event(session, actor_id=ids["owner"], action="step_2", details="Second")
        record_audit_event(session, actor_id=ids["owner"], action="step_3", details="Third")
        session.commit()

        # Delete the middle event
        session.delete(e2)
        session.commit()

        # Verification must detect the broken chain link
        res = verify_audit_chain(session)
        assert res["is_valid"] is False
        assert "Broken chain link" in res["message"]


def test_owner_can_verify_document_audit_chain(audit_test_setup):
    client, ids, current_user_id, _ = audit_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.get(f"/documents/{ids['document']}/audit/verify")
    assert resp.status_code == 200
    assert resp.json()["is_valid"] is True


def test_non_owner_cannot_verify_document_audit_chain(audit_test_setup):
    client, ids, current_user_id, session_factory = audit_test_setup
    current_user_id["value"] = ids["recipient"]

    resp = client.get(f"/documents/{ids['document']}/audit/verify")
    assert resp.status_code == 403

    # Denied attempt must be recorded in audit trail
    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "document_audit_verify_denied"
            )
        ).all()
        assert len(events) >= 1


def test_audit_chain_detects_reordered_events(audit_test_setup):
    _, ids, _, session_factory = audit_test_setup

    with session_factory() as session:
        e1 = record_audit_event(session, actor_id=ids["owner"], action="order_1", details="First")
        e2 = record_audit_event(session, actor_id=ids["owner"], action="order_2", details="Second")
        session.commit()

        # Swap their hashes to simulate an out-of-order tamper
        e1_hash = e1.hash
        e1.hash = e2.hash
        e2.hash = e1_hash
        session.commit()

        res = verify_audit_chain(session)
        assert res["is_valid"] is False

