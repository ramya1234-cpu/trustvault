import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models import AuditEvent, Document, User
from app.schemas import (
    AuditEventResponse,
    AuditVerificationResult,
    DocumentResponse,
    DocumentSearchResult,
    DocumentUpdate,
    UserRoleUpdate,
    UserStatusUpdate,
)


def test_document_model_has_additive_fields():
    doc = Document(
        id=1,
        owner_id=1,
        title="Test Doc",
        category="Finance",
        storage_path="/path/test.pdf",
    )
    assert doc.updated_at is None
    assert doc.category == "Finance"

    now = datetime.now(timezone.utc)
    doc.updated_at = now
    assert doc.updated_at == now


def test_audit_event_model_has_additive_hash_fields():
    event = AuditEvent(
        id=1,
        actor_id=2,
        action="document_uploaded",
        document_id=1,
        details="Uploaded file",
        prev_hash="0" * 64,
        hash="a" * 64,
    )
    assert event.prev_hash == "0" * 64
    assert event.hash == "a" * 64


def test_document_update_schema_validation():
    # Valid partial updates
    update = DocumentUpdate(title="New Title")
    assert update.title == "New Title"
    assert update.category is None

    update2 = DocumentUpdate(category="Confidential")
    assert update2.title is None
    assert update2.category == "Confidential"

    # Empty string validation failure
    with pytest.raises(ValidationError):
        DocumentUpdate(title="")


def test_user_role_update_schema():
    for valid_role in ["administrator", "owner", "viewer"]:
        schema = UserRoleUpdate(role=valid_role)
        assert schema.role == valid_role

    with pytest.raises(ValidationError):
        UserRoleUpdate(role="superuser")


def test_user_status_update_schema():
    status = UserStatusUpdate(is_active=False)
    assert status.is_active is False


def test_document_response_backward_compatibility():
    # Serializing without updated_at
    data = {
        "id": 1,
        "owner_id": 2,
        "title": "Doc",
        "category": "General",
        "created_at": datetime.now(timezone.utc),
    }
    resp = DocumentResponse(**data)
    assert resp.updated_at is None
    assert resp.title == "Doc"

    # Serializing with updated_at
    data["updated_at"] = datetime.now(timezone.utc)
    resp2 = DocumentResponse(**data)
    assert resp2.updated_at is not None


def test_audit_verification_result_schema():
    result = AuditVerificationResult(
        is_valid=True,
        total_events=10,
        verified_events=10,
        message="Audit chain unbroken",
    )
    assert result.is_valid is True
    assert result.tampered_event_id is None
