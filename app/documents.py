
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.auth import get_current_user, get_db
from app.models import AuditEvent, Document, DocumentPermission, User, utc_now
from app.schemas import (
    DocumentResponse,
    DocumentSearchResult,
    DocumentUpdate,
    PermissionGrant,
)
from app.audit import record_audit_event, verify_audit_chain

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
    actor_id: int | None,
    action: str,
    document_id: int | None,
    details: str,
) -> AuditEvent:
    """Add a tamper-evident audit event to the current database transaction."""
    return record_audit_event(
        db,
        actor_id=actor_id,
        action=action,
        document_id=document_id,
        details=details,
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
        write_audit_event(
            db,
            actor_id=owner_id,
            action="document_ownership_denied",
            document_id=document.id,
            details=f"Unauthorized owner action attempt by user_id={owner_id} on document_id={document_id}",
        )
        db.commit()
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
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="File exceeds the 10 MB limit",
        )

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    original_filename = Path(file.filename or "document").name
    safe_filename = f"{uuid4().hex}_{original_filename}"
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


def query_authorized_documents(
    db: Session,
    user: User,
    *,
    q: str | None = None,
    category: str | None = None,
    owner_id: int | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    offset: int = 0,
    limit: int = 100,
) -> list[dict]:
    """Query documents accessible by user (owned or shared with can_read=True).

    Strict authorization isolation ensures users can never discover documents
    they are not authorized to view.
    """
    stmt = (
        select(
            Document,
            (Document.owner_id == user.id).label("is_owner"),
            func.coalesce(DocumentPermission.can_edit, False).label("can_edit"),
        )
        .outerjoin(
            DocumentPermission,
            and_(
                DocumentPermission.document_id == Document.id,
                DocumentPermission.user_id == user.id,
                DocumentPermission.can_read.is_(True),
            ),
        )
        .where(
            or_(
                Document.owner_id == user.id,
                DocumentPermission.id.is_not(None),
            )
        )
    )

    if q and q.strip():
        stmt = stmt.where(Document.title.ilike(f"%{q.strip()}%"))

    if category and category.strip():
        stmt = stmt.where(func.lower(Document.category) == category.strip().lower())

    if owner_id is not None:
        stmt = stmt.where(Document.owner_id == owner_id)

    if start_date is not None:
        stmt = stmt.where(Document.created_at >= start_date)

    if end_date is not None:
        stmt = stmt.where(Document.created_at <= end_date)

    stmt = stmt.order_by(
        Document.created_at.desc(),
        Document.id.desc(),
    ).offset(offset).limit(limit)

    results = db.execute(stmt).all()

    return [
        {
            "id": doc.id,
            "owner_id": doc.owner_id,
            "title": doc.title,
            "category": doc.category,
            "created_at": doc.created_at,
            "updated_at": doc.updated_at,
            "is_owner": is_owner,
            "can_read": True,
            "can_edit": bool(is_owner or can_edit),
        }
        for doc, is_owner, can_edit in results
    ]


def parse_query_datetime(val: str | None) -> datetime | None:
    if not val or not val.strip():
        return None
    candidate = val.strip()
    if " " in candidate and "+" not in candidate:
        parts = candidate.rsplit(" ", 1)
        if len(parts) == 2 and ":" in parts[1]:
            candidate = f"{parts[0]}+{parts[1]}"
    try:
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid date format: {val!r}. Please use ISO 8601 format.",
        ) from exc


@router.get("/")
def list_documents(
    q: str | None = Query(default=None, description="Search term in document title"),
    category: str | None = Query(default=None, description="Filter by category"),
    owner_id: int | None = Query(default=None, description="Filter by owner ID"),
    start_date: str | None = Query(default=None, description="Filter created on or after (ISO 8601)"),
    end_date: str | None = Query(default=None, description="Filter created on or before (ISO 8601)"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return query_authorized_documents(
        db,
        user,
        q=q,
        category=category,
        owner_id=owner_id,
        start_date=parse_query_datetime(start_date),
        end_date=parse_query_datetime(end_date),
        offset=offset,
        limit=limit,
    )


@router.get("/search", response_model=list[DocumentSearchResult])
def search_documents(
    q: str | None = Query(default=None, description="Search term in document title"),
    category: str | None = Query(default=None, description="Filter by category"),
    owner_id: int | None = Query(default=None, description="Filter by owner ID"),
    start_date: str | None = Query(default=None, description="Filter created on or after (ISO 8601)"),
    end_date: str | None = Query(default=None, description="Filter created on or before (ISO 8601)"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Search accessible documents with authorization isolation and combined filters."""
    return query_authorized_documents(
        db,
        user,
        q=q,
        category=category,
        owner_id=owner_id,
        start_date=parse_query_datetime(start_date),
        end_date=parse_query_datetime(end_date),
        offset=offset,
        limit=limit,
    )


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = db.get(Document, document_id)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if document.owner_id != user.id:
        perm = db.scalar(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id == user.id,
                DocumentPermission.can_read.is_(True),
            )
        )
        if perm is None:
            write_audit_event(
                db,
                actor_id=user.id,
                action="document_view_denied",
                document_id=document_id,
                details=f"Unauthorized view attempt on document_id={document_id} by user_id={user.id}",
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )

    return document


@router.patch("/{document_id}", response_model=DocumentResponse)
def update_document(
    document_id: int,
    update_data: DocumentUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = db.get(Document, document_id)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # Enforce edit authorization: owner OR active can_edit permission
    if document.owner_id != user.id:
        perm = db.scalar(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id == user.id,
            )
        )
        if perm is None:
            write_audit_event(
                db,
                actor_id=user.id,
                action="document_edit_denied",
                document_id=document_id,
                details=f"Unauthorized edit attempt on document_id={document_id} by outsider user_id={user.id}",
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )
        elif not perm.can_edit:
            write_audit_event(
                db,
                actor_id=user.id,
                action="document_edit_denied",
                document_id=document_id,
                details=f"Read-only user_id={user.id} attempted to edit document_id={document_id}",
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to edit this document",
            )

    if update_data.title is None and update_data.category is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No update fields provided",
        )

    changes = []
    if update_data.title is not None:
        cleaned_title = update_data.title.strip()
        if not cleaned_title:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Document title cannot be empty",
            )
        document.title = cleaned_title
        changes.append(f"title={cleaned_title!r}")

    if update_data.category is not None:
        cleaned_category = update_data.category.strip()
        if not cleaned_category:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Document category cannot be empty",
            )
        document.category = cleaned_category
        changes.append(f"category={cleaned_category!r}")

    document.updated_at = utc_now()

    write_audit_event(
        db,
        actor_id=user.id,
        action="document_updated",
        document_id=document.id,
        details=f"Updated document {', '.join(changes)}",
    )
    db.commit()
    db.refresh(document)
    return document


@router.delete("/{document_id}")
def delete_document(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = db.get(Document, document_id)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # Strictly owner-only: even users with can_edit=True cannot delete
    if document.owner_id != user.id:
        write_audit_event(
            db,
            actor_id=user.id,
            action="document_delete_denied",
            document_id=document_id,
            details=f"Unauthorized delete attempt on document_id={document_id} by non-owner user_id={user.id}",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can delete this document",
        )

    storage_path = Path(document.storage_path).resolve()
    file_to_delete = None
    if storage_path.is_relative_to(STORAGE_DIR.resolve()) and storage_path.is_file():
        file_to_delete = storage_path

    doc_title = document.title

    try:
        write_audit_event(
            db,
            actor_id=user.id,
            action="document_deleted",
            document_id=document.id,
            details=f"Deleted document title={doc_title!r}",
        )
        db.execute(
            delete(DocumentPermission).where(
                DocumentPermission.document_id == document.id
            )
        )
        db.delete(document)
        db.commit()

        if file_to_delete and file_to_delete.exists():
            file_to_delete.unlink(missing_ok=True)

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Document deleted successfully",
        "document_id": document_id,
    }


@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Allow the owner or a user with active read permission to download."""
    document = db.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if document.owner_id != user.id:
        permission = db.scalar(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id == user.id,
                DocumentPermission.can_read.is_(True),
            )
        )

        if permission is None:
            write_audit_event(
                db,
                actor_id=user.id,
                action="document_download_denied",
                document_id=document_id,
                details=f"Unauthorized download attempt by user_id={user.id} on document_id={document_id}",
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to read this document",
            )

    storage_path = Path(document.storage_path).resolve()

    # Prevent stored paths from escaping the application's storage folder.
    if not storage_path.is_relative_to(STORAGE_DIR.resolve()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid document storage path",
        )

    if not storage_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file not found",
        )

    stored_name = storage_path.name
    download_name = (
        stored_name.split("_", 1)[1]
        if "_" in stored_name
        else "document"
    )

    write_audit_event(
        db,
        actor_id=user.id,
        action="document_downloaded",
        document_id=document.id,
        details=f"Downloaded document title={document.title!r}",
    )
    db.commit()

    return FileResponse(
        path=storage_path,
        filename=download_name,
        media_type="application/octet-stream",
    )


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


@router.get("/{document_id}/audit")
def get_document_audit_log(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = db.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if document.owner_id != user.id:
        write_audit_event(
            db,
            actor_id=user.id,
            action="document_audit_view_denied",
            document_id=document.id,
            details=f"Unauthorized audit log view attempt by user_id={user.id} on document_id={document_id}",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can view its audit log",
        )

    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.document_id == document_id)
        .order_by(
            AuditEvent.created_at.desc(),
            AuditEvent.id.desc(),
        )
    ).all()

    return [
        {
            "id": event.id,
            "actor_id": event.actor_id,
            "action": event.action,
            "document_id": event.document_id,
            "details": event.details,
            "prev_hash": event.prev_hash,
            "hash": event.hash,
            "created_at": event.created_at,
        }
        for event in events
    ]


@router.get("/{document_id}/audit/verify")
def verify_document_audit_chain(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    document = db.get(Document, document_id)
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if document.owner_id != user.id:
        write_audit_event(
            db,
            actor_id=user.id,
            action="document_audit_verify_denied",
            document_id=document.id,
            details=f"Unauthorized audit verify attempt by user_id={user.id} on document_id={document_id}",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can verify its audit log",
        )

    return verify_audit_chain(db)
