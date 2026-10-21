
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import get_current_user, get_db
from app.models import Document, User
from app.schemas import DocumentResponse

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
        raise HTTPException(status_code=415, detail="Unsupported file type")

    content = file.file.read(MAX_FILE_SIZE + 1)

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")

    # Generate a random storage name; never trust the uploaded filename.
    stored_name = uuid4().hex
    file_path = STORAGE_DIR / stored_name

    try:
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

    except Exception:
        db.rollback()
        file_path.unlink(missing_ok=True)
        raise

    finally:
        file.file.close()


@router.get("/", response_model=list[DocumentResponse])
def list_my_documents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list(
        db.scalars(
            select(Document)
            .where(Document.owner_id == user.id)
            .order_by(Document.id.desc())
        ).all()
    )
