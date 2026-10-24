from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import record_audit_event, verify_audit_chain
from app.auth import get_db, require_admin
from app.models import AuditEvent, User
from app.schemas import (
    AuditEventResponse,
    AuditVerificationResult,
    UserResponse,
    UserRoleUpdate,
    UserStatusUpdate,
)

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get("/users", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[User]:
    """Administrator-only: list all system users."""
    users = db.scalars(
        select(User).order_by(User.id.asc())
    ).all()
    return list(users)


@router.patch("/users/{user_id}/status", response_model=UserResponse)
def update_user_status(
    user_id: int,
    status_data: UserStatusUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    """Administrator-only: activate or deactivate a user account.

    Guards against self-deactivation and deactivating the last active administrator.
    """
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent administrator self-deactivation
    if target.id == admin.id and not status_data.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account",
        )

    # Prevent deactivating the last active administrator
    if target.role == "administrator" and not status_data.is_active:
        active_admins_count = db.scalar(
            select(func.count(User.id)).where(
                User.role == "administrator",
                User.is_active.is_(True),
            )
        )
        if (active_admins_count or 0) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate the last active administrator",
            )

    previous_status = target.is_active
    target.is_active = status_data.is_active

    record_audit_event(
        db,
        actor_id=admin.id,
        action="admin_user_status_updated",
        details=(
            f"Admin {admin.id} changed user {target.id} status "
            f"from {previous_status} to {status_data.is_active}"
        ),
    )
    db.commit()
    db.refresh(target)
    return target


@router.patch("/users/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_data: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    """Administrator-only: assign user role (administrator, owner, viewer).

    Guards against demoting the last active administrator.
    """
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent demoting the last active administrator
    if target.role == "administrator" and role_data.role != "administrator":
        active_admins_count = db.scalar(
            select(func.count(User.id)).where(
                User.role == "administrator",
                User.is_active.is_(True),
            )
        )
        if (active_admins_count or 0) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last active administrator",
            )

    previous_role = target.role
    target.role = role_data.role

    record_audit_event(
        db,
        actor_id=admin.id,
        action="admin_user_role_updated",
        details=(
            f"Admin {admin.id} changed user {target.id} role "
            f"from {previous_role} to {role_data.role}"
        ),
    )
    db.commit()
    db.refresh(target)
    return target


@router.get("/audit", response_model=list[AuditEventResponse])
def get_system_audit_log(
    action: str | None = None,
    actor_id: int | None = None,
    document_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[AuditEvent]:
    """Administrator-only: inspect system-wide audit metadata.

    Exposes audit metadata without disclosing document contents, passwords, or tokens.
    """
    stmt = select(AuditEvent)

    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if document_id:
        stmt = stmt.where(AuditEvent.document_id == document_id)

    stmt = stmt.order_by(AuditEvent.id.desc()).offset(offset).limit(limit)
    events = db.scalars(stmt).all()
    return list(events)


@router.get("/audit/verify", response_model=AuditVerificationResult)
def verify_system_audit_chain(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict:
    """Administrator-only: verify cryptographic hash-chain integrity across all events."""
    return verify_audit_chain(db)
