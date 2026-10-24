import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user, get_db
from app.main import app
from app import documents as documents_module
from app.models import AuditEvent, Base, Document, DocumentPermission, User
from app.audit import verify_audit_chain


@pytest.fixture
def lifecycle_test_setup(tmp_path, monkeypatch):
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
        email="doc_owner_life@example.com",
        full_name="Document Owner",
        password_hash="test-hash",
        role="owner",
        is_active=True,
    )
    editor = User(
        email="doc_editor_life@example.com",
        full_name="Document Editor",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    viewer = User(
        email="doc_viewer_life@example.com",
        full_name="Document Viewer",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    outsider = User(
        email="doc_outsider_life@example.com",
        full_name="Document Outsider",
        password_hash="test-hash",
        role="viewer",
        is_active=True,
    )
    db.add_all([owner, editor, viewer, outsider])
    db.commit()

    # Create physical test document file
    storage_file = tmp_path / "lifecycle_test.txt"
    storage_file.write_bytes(b"Secure lifecycle test file content")

    doc = Document(
        owner_id=owner.id,
        title="Original Title",
        category="Initial Category",
        storage_path=str(storage_file),
    )
    db.add(doc)
    db.commit()

    # Grant editor can_edit=True
    p_edit = DocumentPermission(
        document_id=doc.id,
        user_id=editor.id,
        can_read=True,
        can_edit=True,
        granted_by=owner.id,
    )
    # Grant viewer can_read=True, can_edit=False
    p_view = DocumentPermission(
        document_id=doc.id,
        user_id=viewer.id,
        can_read=True,
        can_edit=False,
        granted_by=owner.id,
    )
    db.add_all([p_edit, p_view])
    db.commit()

    ids = {
        "owner": owner.id,
        "editor": editor.id,
        "viewer": viewer.id,
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
            yield client, ids, current_user_id, TestingSessionLocal, storage_file
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_owner_can_update_document_metadata(lifecycle_test_setup):
    client, ids, current_user_id, session_factory, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.patch(
        f"/documents/{ids['document']}",
        json={"title": "Updated by Owner", "category": "Updated Category"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Updated by Owner"
    assert data["category"] == "Updated Category"
    assert data["updated_at"] is not None

    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.document_id == ids["document"],
                AuditEvent.action == "document_updated",
            )
        ).all()
        assert len(events) >= 1
        assert "Updated by Owner" in events[0].details


def test_recipient_with_edit_permission_can_update_document(lifecycle_test_setup):
    client, ids, current_user_id, _, _ = lifecycle_test_setup
    current_user_id["value"] = ids["editor"]

    resp = client.patch(
        f"/documents/{ids['document']}",
        json={"title": "Updated by Editor"},
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated by Editor"


def test_read_only_recipient_cannot_update_document(lifecycle_test_setup):
    client, ids, current_user_id, session_factory, _ = lifecycle_test_setup
    current_user_id["value"] = ids["viewer"]

    resp = client.patch(
        f"/documents/{ids['document']}",
        json={"title": "Unauthorized Edit Attempt"},
    )
    assert resp.status_code == 403
    assert "You do not have permission to edit this document" in resp.json()["detail"]

    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "document_edit_denied")
        ).all()
        assert len(events) >= 1
        assert events[0].actor_id == ids["viewer"]


def test_outsider_cannot_update_document(lifecycle_test_setup):
    client, ids, current_user_id, session_factory, _ = lifecycle_test_setup
    current_user_id["value"] = ids["outsider"]

    resp = client.patch(
        f"/documents/{ids['document']}",
        json={"title": "Outsider Edit Attempt"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Document not found"

    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "document_edit_denied")
        ).all()
        assert len(events) >= 1
        assert events[0].actor_id == ids["outsider"]


def test_update_document_with_invalid_metadata(lifecycle_test_setup):
    client, ids, current_user_id, _, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    # Empty payload
    resp1 = client.patch(f"/documents/{ids['document']}", json={})
    assert resp1.status_code == 400

    # Blank title
    resp2 = client.patch(f"/documents/{ids['document']}", json={"title": "   "})
    assert resp2.status_code == 400

    # Blank category
    resp3 = client.patch(f"/documents/{ids['document']}", json={"category": "   "})
    assert resp3.status_code == 400


def test_update_nonexistent_document_returns_404(lifecycle_test_setup):
    client, _, current_user_id, _, _ = lifecycle_test_setup
    resp = client.patch("/documents/999999", json={"title": "Nonexistent"})
    assert resp.status_code == 404


def test_owner_can_delete_document_and_cleans_up_storage(lifecycle_test_setup):
    client, ids, current_user_id, session_factory, storage_file = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    assert storage_file.exists()

    resp = client.delete(f"/documents/{ids['document']}")
    assert resp.status_code == 200
    assert resp.json()["message"] == "Document deleted successfully"

    # Physical file must be removed from storage
    assert not storage_file.exists()

    with session_factory() as session:
        # Document record deleted
        doc = session.get(Document, ids["document"])
        assert doc is None

        # Associated permissions deleted
        perms = session.scalars(
            select(DocumentPermission).where(
                DocumentPermission.document_id == ids["document"]
            )
        ).all()
        assert len(perms) == 0

        # Audit events preserved
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "document_deleted"
            )
        ).all()
        assert len(events) == 1
        assert events[0].actor_id == ids["owner"]

        # Audit chain remains unbroken and valid
        chain_res = verify_audit_chain(session)
        assert chain_res["is_valid"] is True


def test_user_with_edit_permission_cannot_delete_document(lifecycle_test_setup):
    client, ids, current_user_id, session_factory, storage_file = lifecycle_test_setup
    current_user_id["value"] = ids["editor"]

    resp = client.delete(f"/documents/{ids['document']}")
    assert resp.status_code == 403
    assert "Only the document owner can delete this document" in resp.json()["detail"]

    # File and document must remain intact
    assert storage_file.exists()

    with session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "document_delete_denied"
            )
        ).all()
        assert len(events) >= 1
        assert events[0].actor_id == ids["editor"]


def test_outsider_cannot_delete_document(lifecycle_test_setup):
    client, ids, current_user_id, _, storage_file = lifecycle_test_setup
    current_user_id["value"] = ids["outsider"]

    resp = client.delete(f"/documents/{ids['document']}")
    assert resp.status_code == 403
    assert storage_file.exists()


def test_delete_nonexistent_document_returns_404(lifecycle_test_setup):
    client, _, current_user_id, _, _ = lifecycle_test_setup
    resp = client.delete("/documents/999999")
    assert resp.status_code == 404


def test_get_document_details(lifecycle_test_setup):
    client, ids, current_user_id, _, _ = lifecycle_test_setup

    # Owner can get details
    current_user_id["value"] = ids["owner"]
    resp1 = client.get(f"/documents/{ids['document']}")
    assert resp1.status_code == 200
    assert resp1.json()["id"] == ids["document"]

    # Reader can get details
    current_user_id["value"] = ids["viewer"]
    resp2 = client.get(f"/documents/{ids['document']}")
    assert resp2.status_code == 200

    # Outsider gets 404 (does not leak existence)
    current_user_id["value"] = ids["outsider"]
    resp3 = client.get(f"/documents/{ids['document']}")
    assert resp3.status_code == 404


def test_upload_validation_unsupported_mimetype(lifecycle_test_setup):
    client, ids, current_user_id, _, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.post(
        "/documents/upload?title=Malicious&category=General",
        files={"file": ("exploit.exe", b"\x4d\x5a\x90", "application/x-msdownload")},
    )
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.json()["detail"]


def test_upload_validation_empty_file(lifecycle_test_setup):
    client, ids, current_user_id, _, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.post(
        "/documents/upload?title=Empty&category=General",
        files={"file": ("empty.txt", b"", "text/plain")},
    )
    assert resp.status_code == 400
    assert "Uploaded file is empty" in resp.json()["detail"]


def test_upload_validation_blank_title(lifecycle_test_setup):
    client, ids, current_user_id, _, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.post(
        "/documents/upload?title=%20%20%20&category=General",
        files={"file": ("test.txt", b"Hello", "text/plain")},
    )
    assert resp.status_code == 400
    assert "Document title cannot be empty" in resp.json()["detail"]


def test_upload_validation_oversized_file(lifecycle_test_setup, monkeypatch):
    client, ids, current_user_id, _, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    # Temporarily set max file size to 10 bytes to test 413
    monkeypatch.setattr(documents_module, "MAX_FILE_SIZE", 10)

    resp = client.post(
        "/documents/upload?title=Oversized&category=General",
        files={"file": ("large.txt", b"This file content definitely exceeds ten bytes", "text/plain")},
    )
    assert resp.status_code == 413
    assert "exceeds" in resp.json()["detail"]


def test_upload_filename_traversal_prevented(lifecycle_test_setup):
    client, ids, current_user_id, session_factory, _ = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    resp = client.post(
        "/documents/upload?title=TraversalTest&category=General",
        files={"file": ("../../../../etc/passwd", b"root:x:0:0:", "text/plain")},
    )
    assert resp.status_code == 201
    doc_id = resp.json()["id"]

    with session_factory() as session:
        doc = session.get(Document, doc_id)
        # Ensure Path(doc.storage_path) is contained safely within STORAGE_DIR
        storage_dir = documents_module.STORAGE_DIR.resolve()
        file_path = Path(doc.storage_path).resolve()
        assert file_path.is_relative_to(storage_dir)
        assert file_path.name.endswith("passwd")


def test_document_deletion_with_foreign_keys_preserves_audit_trail(lifecycle_test_setup):
    """Verify document deletion succeeds and audit trail is preserved with SQLite foreign keys enabled."""
    client, ids, current_user_id, session_factory, storage_file = lifecycle_test_setup
    current_user_id["value"] = ids["owner"]

    # Explicitly enable foreign keys on the session connection
    with session_factory() as session:
        session.connection().execute(__import__("sqlalchemy").text("PRAGMA foreign_keys = ON;"))
        session.commit()

    # Delete the document
    resp = client.delete(f"/documents/{ids['document']}")
    assert resp.status_code == 200
    assert resp.json()["message"] == "Document deleted successfully"

    # Confirm storage file removed and document deleted
    assert not storage_file.exists()
    with session_factory() as session:
        assert session.get(Document, ids["document"]) is None

        # Verify audit events for this document still exist and hash chain is intact
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.document_id == ids["document"])
        ).all()
        assert len(events) >= 1
        actions = [e.action for e in events]
        assert "document_deleted" in actions

        chain_result = verify_audit_chain(session)
        assert chain_result["is_valid"] is True


