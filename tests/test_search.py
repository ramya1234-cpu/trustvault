from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user, get_db
from app.main import app
from app import documents as documents_module
from app.models import Base, Document, DocumentPermission, User


@pytest.fixture
def search_test_setup(tmp_path, monkeypatch):
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
    alice = User(
        email="alice_search@example.com",
        full_name="Alice Search",
        password_hash="test-hash",
        role="owner",
        is_active=True,
    )
    bob = User(
        email="bob_search@example.com",
        full_name="Bob Search",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    charlie = User(
        email="charlie_search@example.com",
        full_name="Charlie Search",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    db.add_all([alice, bob, charlie])
    db.commit()

    now = datetime.now(timezone.utc)

    # Alice's documents
    d1 = Document(
        owner_id=alice.id,
        title="Q1 Financial Report",
        category="Finance",
        storage_path="d1.txt",
        created_at=now - timedelta(days=10),
    )
    d2 = Document(
        owner_id=alice.id,
        title="Employment Contract NDA",
        category="Legal",
        storage_path="d2.txt",
        created_at=now - timedelta(days=5),
    )
    d3 = Document(
        owner_id=alice.id,
        title="Company Security Guidelines",
        category="Security",
        storage_path="d3.txt",
        created_at=now - timedelta(days=1),
    )

    # Bob's private document
    d4 = Document(
        owner_id=bob.id,
        title="Bob Private Notes",
        category="Personal",
        storage_path="d4.txt",
        created_at=now,
    )

    db.add_all([d1, d2, d3, d4])
    db.commit()

    # Share d1 with Bob (read-only)
    p1 = DocumentPermission(
        document_id=d1.id,
        user_id=bob.id,
        can_read=True,
        can_edit=False,
        granted_by=alice.id,
    )
    # Share d2 with Bob (edit)
    p2 = DocumentPermission(
        document_id=d2.id,
        user_id=bob.id,
        can_read=True,
        can_edit=True,
        granted_by=alice.id,
    )
    db.add_all([p1, p2])
    db.commit()

    ids = {
        "alice": alice.id,
        "bob": bob.id,
        "charlie": charlie.id,
        "d1": d1.id,
        "d2": d2.id,
        "d3": d3.id,
        "d4": d4.id,
    }
    db.close()

    current_user_id = {"value": ids["alice"]}

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
            yield client, ids, current_user_id, TestingSessionLocal, now
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_owner_can_search_by_title_keyword(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    current_user_id["value"] = ids["alice"]

    resp = client.get("/documents/search?q=financial")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["id"] == ids["d1"]
    assert items[0]["title"] == "Q1 Financial Report"
    assert items[0]["is_owner"] is True


def test_search_by_category(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    current_user_id["value"] = ids["alice"]

    resp = client.get("/documents/search?category=legal")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["id"] == ids["d2"]
    assert items[0]["category"] == "Legal"


def test_search_by_owner_id(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    current_user_id["value"] = ids["alice"]

    resp = client.get(f"/documents/search?owner_id={ids['alice']}")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 3


def test_search_by_date_range(search_test_setup):
    client, ids, current_user_id, _, now = search_test_setup
    current_user_id["value"] = ids["alice"]

    start = (now - timedelta(days=6)).isoformat()
    end = (now - timedelta(days=2)).isoformat()

    resp = client.get(
        "/documents/search",
        params={"start_date": start, "end_date": end},
    )
    assert resp.status_code == 200
    items = resp.json()
    # d2 (5 days ago) is between 6 and 2 days ago
    assert len(items) == 1
    assert items[0]["id"] == ids["d2"]


def test_combined_search_filters(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    current_user_id["value"] = ids["alice"]

    resp = client.get("/documents/search?q=guidelines&category=Security")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["id"] == ids["d3"]


def test_search_pagination(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    current_user_id["value"] = ids["alice"]

    # 3 total documents for Alice, page size 2
    resp1 = client.get("/documents/search?limit=2&offset=0")
    assert resp1.status_code == 200
    assert len(resp1.json()) == 2

    resp2 = client.get("/documents/search?limit=2&offset=2")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1


def test_search_authorization_isolation_outsider_gets_zero(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    # Charlie is an outsider to Alice's and Bob's documents
    current_user_id["value"] = ids["charlie"]

    resp1 = client.get("/documents/search?q=financial")
    assert resp1.status_code == 200
    assert resp1.json() == []

    resp2 = client.get("/documents/search?q=notes")
    assert resp2.status_code == 200
    assert resp2.json() == []

    resp3 = client.get("/documents/search")
    assert resp3.status_code == 200
    assert resp3.json() == []


def test_shared_recipient_sees_shared_documents_in_search(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup
    # Bob has read access to d1 and edit access to d2, plus owns d4
    current_user_id["value"] = ids["bob"]

    resp = client.get("/documents/search?q=financial")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["id"] == ids["d1"]
    assert items[0]["is_owner"] is False
    assert items[0]["can_read"] is True
    assert items[0]["can_edit"] is False

    # Check d2 where Bob has can_edit
    resp2 = client.get("/documents/search?q=contract")
    assert resp2.status_code == 200
    items2 = resp2.json()
    assert len(items2) == 1
    assert items2[0]["id"] == ids["d2"]
    assert items2[0]["is_owner"] is False
    assert items2[0]["can_edit"] is True


def test_revoked_recipient_cannot_see_document_in_search(search_test_setup):
    client, ids, current_user_id, _, _ = search_test_setup

    # Alice revokes Bob's access to d1
    current_user_id["value"] = ids["alice"]
    del_resp = client.delete(f"/documents/{ids['d1']}/share/{ids['bob']}")
    assert del_resp.status_code == 204

    # Bob searches for financial report
    current_user_id["value"] = ids["bob"]
    resp = client.get("/documents/search?q=financial")
    assert resp.status_code == 200
    assert resp.json() == []
