
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user, get_db
from app.models import AuditEvent, Document, DocumentPermission, User
from app.schemas import PermissionGrant

router = APIRouter(prefix="/documents", tags=["Documents"])

STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage"
MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "text/plain",
    "image/png",
    "image/jpeg",
}


def write_audit_event(
    db: Session,
    *,
    actor_id: int,
    action: str,
    document_id: int,
    details: str,
) -> None:
    """Add an audit event to the current database transaction."""
    db.add(
        AuditEvent(
            actor_id=actor_id,
            action=action,
            document_id=document_id,
            details=details,
        )
    )


def get_owned_document(
    db: Session,
    document_id: int,
    owner_id: int,
) -> Document:
    document = db.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if document.owner_id != owner_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can perform this action",
        )

    return document


@router.post("/upload", status_code=status.HTTP_201_CREATED)
def upload_document(
    file: UploadFile = File(...),
    title: str = "Untitled document",
    category: str = "General",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not title.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Document title cannot be empty",
        )

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file type",
        )

    content = file.file.read()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds the 10 MB limit",
        )

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    safe_filename = f"{uuid4().hex}_{Path(file.filename or 'document').name}"
    storage_path = STORAGE_DIR / safe_filename

    try:
        storage_path.write_bytes(content)

        document = Document(
            owner_id=user.id,
            title=title.strip(),
            category=category.strip() or "General",
            storage_path=str(storage_path),
        )
        db.add(document)
        db.flush()

        write_audit_event(
            db,
            actor_id=user.id,
            action="document_uploaded",
            document_id=document.id,
            details=f"Uploaded document title={document.title!r}",
        )

        db.commit()
        db.refresh(document)

        return {
            "id": document.id,
            "owner_id": document.owner_id,
            "title": document.title,
            "category": document.category,
            "created_at": document.created_at,
        }

    except Exception:
        db.rollback()
        if storage_path.exists():
            storage_path.unlink()
        raise

    finally:
        file.file.close()


@router.get("/")
def list_documents(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Owners can see their own documents.
    owned_documents = db.scalars(
        select(Document).where(Document.owner_id == user.id)
    ).all()

    # Recipients can see documents only while read permission is active.
    shared_documents = db.scalars(
        select(Document)
        .join(
            DocumentPermission,
            DocumentPermission.document_id == Document.id,
        )
        .where(
            DocumentPermission.user_id == user.id,
            DocumentPermission.can_read.is_(True),
        )
    ).all()

    documents_by_id = {
        document.id: document
        for document in [*owned_documents, *shared_documents]
    }

    return [
        {
            "id": document.id,
            "owner_id": document.owner_id,
            "title": document.title,
            "category": document.category,
            "created_at": document.created_at,
        }
        for document in documents_by_id.values()
    ]


@router.post(
    "/{document_id}/share",
    status_code=status.HTTP_201_CREATED,
)
def share_document(
    document_id: int,
    permission_data: PermissionGrant,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = get_owned_document(db, document_id, user.id)

    recipient = db.get(User, permission_data.user_id)

    if recipient is None or not recipient.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active recipient not found",
        )

    if recipient.id == user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot share a document with yourself",
        )

    existing_permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == recipient.id,
        )
    )

    if existing_permission is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Permission already exists for this user",
        )

    permission = DocumentPermission(
        document_id=document.id,
        user_id=recipient.id,
        can_read=permission_data.can_read,
        can_edit=permission_data.can_edit,
        granted_by=user.id,
    )

    try:
        db.add(permission)
        db.flush()

        write_audit_event(
            db,
            actor_id=user.id,
            action="document_shared",
            document_id=document.id,
            details=(
                f"Shared with user_id={recipient.id}; "
                f"can_read={permission_data.can_read}; "
                f"can_edit={permission_data.can_edit}"
            ),
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Document shared successfully",
        "document_id": document.id,
        "user_id": recipient.id,
        "can_read": permission_data.can_read,
        "can_edit": permission_data.can_edit,
    }


@router.delete(
    "/{document_id}/share/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_document_access(
    document_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = get_owned_document(db, document_id, user.id)

    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == user_id,
        )
    )

    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found",
        )

    try:
        write_audit_event(
            db,
            actor_id=user.id,
            action="document_access_revoked",
            document_id=document.id,
            details=f"Revoked access for user_id={user_id}",
        )

        db.delete(permission)
        db.commit()

    except Exception:
        db.rollback()
        raise

    return None
