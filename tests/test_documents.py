
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user, get_db
from app.main import app
from app.models import Base, User, Document


@pytest.fixture
def test_setup():
    # Separate in-memory database; does not use your PostgreSQL database.
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

    db = TestingSessionLocal()

    owner = User(
        email="owner@example.com",
        full_name="Owner",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    recipient = User(
        email="recipient@example.com",
        full_name="Recipient",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    outsider = User(
        email="outsider@example.com",
        full_name="Outsider",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )

    db.add_all([owner, recipient, outsider])
    db.commit()

    db.refresh(owner)
    db.refresh(recipient)
    db.refresh(outsider)

    document = Document(
        owner_id=owner.id,
        title="Test document",
        category="General",
        storage_path="test-document.txt",
    )

    db.add(document)
    db.commit()
    db.refresh(document)

    ids = {
        "owner": owner.id,
        "recipient": recipient.id,
        "outsider": outsider.id,
        "document": document.id,
    }

    db.close()

    current_user_id = {"value": ids["owner"]}

    # Correctly yield a SQLAlchemy Session to FastAPI.
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
            yield client, ids, current_user_id
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_non_owner_cannot_share_document(test_setup):
    client, ids, current_user_id = test_setup
    current_user_id["value"] = ids["recipient"]

    response = client.post(
        f"/documents/{ids['document']}/share",
        json={
            "user_id": ids["outsider"],
            "can_read": True,
            "can_edit": False,
        },
    )

    assert response.status_code == 403


def test_non_owner_cannot_revoke_access(test_setup):
    client, ids, current_user_id = test_setup
    current_user_id["value"] = ids["recipient"]

    response = client.delete(
        f"/documents/{ids['document']}/share/{ids['outsider']}"
    )

    assert response.status_code == 403


def test_owner_can_share_and_recipient_can_see_document(test_setup):
    client, ids, current_user_id = test_setup

    response = client.post(
        f"/documents/{ids['document']}/share",
        json={
            "user_id": ids["recipient"],
            "can_read": True,
            "can_edit": False,
        },
    )

    assert response.status_code == 201

    current_user_id["value"] = ids["recipient"]
    response = client.get("/documents/")

    assert response.status_code == 200
    assert any(
        item["id"] == ids["document"]
        for item in response.json()
    )


def test_revoked_recipient_no_longer_sees_document(test_setup):
    client, ids, current_user_id = test_setup

    share_response = client.post(
        f"/documents/{ids['document']}/share",
        json={
            "user_id": ids["recipient"],
            "can_read": True,
            "can_edit": False,
        },
    )

    assert share_response.status_code == 201

    revoke_response = client.delete(
        f"/documents/{ids['document']}/share/{ids['recipient']}"
    )

    assert revoke_response.status_code == 204

    current_user_id["value"] = ids["recipient"]
    response = client.get("/documents/")

    assert response.status_code == 200
    assert all(
        item["id"] != ids["document"]
        for item in response.json()
    )


def test_duplicate_share_is_rejected(test_setup):
    client, ids, _ = test_setup

    payload = {
        "user_id": ids["recipient"],
        "can_read": True,
        "can_edit": False,
    }

    first = client.post(
        f"/documents/{ids['document']}/share",
        json=payload,
    )
    second = client.post(
        f"/documents/{ids['document']}/share",
        json=payload,
    )

    assert first.status_code == 201
    assert second.status_code == 409


def test_sharing_nonexistent_document_returns_404(test_setup):
    client, ids, _ = test_setup

    response = client.post(
        "/documents/999999/share",
        json={
            "user_id": ids["recipient"],
            "can_read": True,
            "can_edit": False,
        },
    )

    assert response.status_code == 404
