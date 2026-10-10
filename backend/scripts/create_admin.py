"""Administrative user bootstrap script for CyberShield.

Provides a secure, non-interactive or interactive CLI mechanism to create or promote
the initial platform administrator without raw database editing or public API exposure.

Usage:
    Interactive (prompts for masked password):
        python scripts/create_admin.py --email admin@example.com

    Non-interactive (using environment variables):
        ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD="SecurePass123!" python scripts/create_admin.py
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.database import SessionLocal  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.audit import AuditLog  # noqa: E402
from app.security.hashing import hash_password, validate_password_strength  # noqa: E402


def create_or_promote_admin(
    email: str,
    password: str | None = None,
    full_name: str | None = None,
) -> bool:
    """Create or promote a user to administrator role with password hashing and audit logging."""
    email = email.strip().lower()
    if not email or "@" not in email:
        print("[ERROR] Invalid email address format.", file=sys.stderr)
        return False

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            print(f"[INFO] Existing user '{email}' found with role '{user.role}'.")
            if user.role == "admin" and user.is_active:
                print(f"[INFO] User '{email}' is already an active administrator.")
                return True

            user.role = "admin"
            user.is_active = True
            if password:
                is_valid, err_msg = validate_password_strength(password)
                if not is_valid:
                    print(f"[ERROR] Password complexity failed: {err_msg}", file=sys.stderr)
                    return False
                user.hashed_password = hash_password(password)

            audit_entry = AuditLog(
                user_id=user.id,
                action="ADMIN_BOOTSTRAP_PROMOTED",
                resource_type="USER",
                resource_id=user.id,
                ip_address="127.0.0.1",
                user_agent="CLI-bootstrap",
                status_code=200,
                details={"email": email, "action": "promoted_to_admin"},
            )
            db.add(audit_entry)
            db.commit()
            print(f"[SUCCESS] User '{email}' successfully promoted to administrator.")
            return True
        else:
            if not password:
                print(
                    "[ERROR] Password required to create a new administrator account.",
                    file=sys.stderr,
                )
                return False

            is_valid, err_msg = validate_password_strength(password)
            if not is_valid:
                print(f"[ERROR] Password complexity failed: {err_msg}", file=sys.stderr)
                return False

            new_user = User(
                email=email,
                hashed_password=hash_password(password),
                full_name=full_name or "System Administrator",
                role="admin",
                is_active=True,
            )
            db.add(new_user)
            db.flush()

            audit_entry = AuditLog(
                user_id=new_user.id,
                action="ADMIN_BOOTSTRAP_CREATED",
                resource_type="USER",
                resource_id=new_user.id,
                ip_address="127.0.0.1",
                user_agent="CLI-bootstrap",
                status_code=201,
                details={"email": email, "action": "created_admin"},
            )
            db.add(audit_entry)
            db.commit()
            print(f"[SUCCESS] New administrator account '{email}' created successfully.")
            return True
    except Exception as exc:
        db.rollback()
        print(f"[ERROR] Failed to bootstrap administrator: {exc}", file=sys.stderr)
        return False
    finally:
        db.close()


def main() -> None:
    """Parse CLI arguments or environment variables to bootstrap administrator."""
    parser = argparse.ArgumentParser(description="Bootstrap CyberShield Administrator")
    parser.add_argument("--email", help="Administrator email address")
    parser.add_argument("--name", help="Full name for administrator", default=None)
    args = parser.parse_args()

    email = args.email or os.getenv("ADMIN_EMAIL")
    if not email:
        try:
            email = input("Enter administrator email: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

    password = os.getenv("ADMIN_PASSWORD")
    if not password:
        try:
            password = getpass.getpass("Enter administrator password: ")
            confirm = getpass.getpass("Confirm administrator password: ")
            if password != confirm:
                print("[ERROR] Passwords do not match.", file=sys.stderr)
                sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

    success = create_or_promote_admin(email=email, password=password, full_name=args.name)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
