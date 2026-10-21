
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from app.auth import get_current_user, get_db
from app.models import Document, DocumentPermission, User
from app.schemas import DocumentResponse, PermissionGrant

router = APIRouter(prefix="/documents", tags=["Documents"])

STORAGE_DIR = Path("storage").resolve()
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_TYPES = {
    "application/pdf",
    "text/plain",
    "image/png",
    "image/jpeg",
}


@router.post("/upload", response_model=DocumentResponse, status_code=201)
def upload_document(
    title: str,
    category: str = "General",
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type",
        )

    file_path = None

    try:
        content = file.file.read(MAX_FILE_SIZE + 1)

        if not content:
            raise HTTPException(status_code=400, detail="Empty file")

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File exceeds 10 MB limit",
            )

        if not title.strip():
            raise HTTPException(
                status_code=422,
                detail="Document title cannot be empty",
            )

        # Use a random storage name instead of the uploaded filename.
        stored_name = uuid4().hex
        file_path = STORAGE_DIR / stored_name

        with file_path.open("xb") as destination:
            destination.write(content)

        document = Document(
            owner_id=user.id,
            title=title.strip(),
            category=category.strip() or "General",
            storage_path=str(file_path),
        )

        db.add(document)
        db.commit()
        db.refresh(document)

        return document

    except HTTPException:
        if file_path is not None:
            file_path.unlink(missing_ok=True)
        raise

    except Exception:
        db.rollback()
        if file_path is not None:
            file_path.unlink(missing_ok=True)
        raise

    finally:
        file.file.close()


@router.get("/", response_model=list[DocumentResponse])
def list_my_documents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Owners see their documents. Recipients see documents
    # only when they have an active read permission.
    permission_exists = (
        select(DocumentPermission.id)
        .where(
            DocumentPermission.document_id == Document.id,
            DocumentPermission.user_id == user.id,
            DocumentPermission.can_read.is_(True),
        )
        .exists()
    )

    statement = (
        select(Document)
        .where(
            or_(
                Document.owner_id == user.id,
                permission_exists,
            )
        )
        .order_by(Document.id.desc())
    )

    return list(db.scalars(statement).all())


@router.post("/{document_id}/share", status_code=201)
def share_document(
    document_id: int,
    permission: PermissionGrant,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    if document.owner_id != user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the document owner can share this document",
        )

    recipient = db.get(User, permission.user_id)

    if recipient is None or not recipient.is_active:
        raise HTTPException(
            status_code=404,
            detail="Recipient not found",
        )

    if recipient.id == user.id:
        raise HTTPException(
            status_code=400,
            detail="You already own this document",
        )

    existing = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == recipient.id,
        )
    )

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="Document is already shared with this user",
        )

    grant = DocumentPermission(
        document_id=document_id,
        user_id=recipient.id,
        can_read=permission.can_read,
        can_edit=permission.can_edit,
        granted_by=user.id,
    )

    try:
        db.add(grant)
        db.commit()
        db.refresh(grant)
    except Exception:
        db.rollback()
        raise

    return {
        "message": "Document shared successfully",
        "document_id": document_id,
        "user_id": recipient.id,
        "can_read": grant.can_read,
        "can_edit": grant.can_edit,
    }


@router.delete("/{document_id}/share/{user_id}", status_code=204)
def revoke_document_access(
    document_id: int,
    user_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    if document.owner_id != user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the document owner can revoke access",
        )

    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        )
    )

    if permission is None:
        raise HTTPException(
            status_code=404,
            detail="Document permission not found",
        )

    db.delete(permission)
    db.commit()
    return None
