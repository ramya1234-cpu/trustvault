import sys

from sqlalchemy import select

from app.audit import record_audit_event
from app.database import SessionLocal
from app.models import User


def promote_to_admin(email: str) -> bool:
    """Promote an existing registered user to the administrator role safely."""
    cleaned_email = email.strip().lower()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == cleaned_email))
        if user is None:
            print(f"Error: User with email '{cleaned_email}' not found.")
            print("Please register the user first via /auth/register, then run this bootstrap tool.")
            return False

        if user.role == "administrator" and user.is_active:
            print(f"User '{cleaned_email}' is already an active administrator.")
            return True

        previous_role = user.role
        user.role = "administrator"
        user.is_active = True

        record_audit_event(
            db,
            actor_id=user.id,
            action="admin_bootstrapped",
            details=f"User {user.id} ({cleaned_email}) promoted from {previous_role} to administrator via bootstrap utility",
        )
        db.commit()
        print(f"Success: User '{cleaned_email}' (ID {user.id}) is now an administrator.")
        return True


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m app.bootstrap_admin <user_email>")
        sys.exit(1)

    target_email = sys.argv[1]
    success = promote_to_admin(target_email)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
