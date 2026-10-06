"""Authentication and user management REST API endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    UserRole,
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
)
from app.security.hashing import hash_password, verify_password
from app.security.jwt import create_access_token
from app.security.dependencies import (
    get_current_active_user,
    require_admin,
    require_analyst,
    require_viewer,
)
from app.utils.audit_helper import record_audit_log, get_client_ip, get_user_agent

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new platform user",
)
def register(
    user_in: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Register a new user account with Argon2id password hashing and audit logging."""
    ip = get_client_ip(request)
    ua = get_user_agent(request)

    # Check for existing user with this email
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        record_audit_log(
            db=db,
            action="USER_REGISTER_DUPLICATE",
            resource_type="USER",
            status_code=status.HTTP_409_CONFLICT,
            ip_address=ip,
            user_agent=ua,
            details={"attempted_email": user_in.email},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists.",
        )

    # Prevent self-registration with elevated 'admin' role
    if user_in.role == UserRole.ADMIN:
        record_audit_log(
            db=db,
            action="USER_REGISTER_UNAUTHORIZED_ROLE",
            resource_type="USER",
            status_code=status.HTTP_403_FORBIDDEN,
            ip_address=ip,
            user_agent=ua,
            details={"attempted_role": "admin", "email": user_in.email},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-registration with 'admin' role is prohibited.",
        )

    # Hash password securely using Argon2id
    hashed = hash_password(user_in.password)

    new_user = User(
        email=user_in.email,
        hashed_password=hashed,
        full_name=user_in.full_name,
        role=user_in.role.value,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Record registration audit log
    record_audit_log(
        db=db,
        action="USER_REGISTER_SUCCESS",
        resource_type="USER",
        resource_id=new_user.id,
        user_id=new_user.id,
        status_code=status.HTTP_201_CREATED,
        ip_address=ip,
        user_agent=ua,
        details={"role": new_user.role, "email": new_user.email},
    )

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and obtain JWT access token",
)
def login(
    login_in: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate user with email and password, issuing a JWT access token."""
    ip = get_client_ip(request)
    ua = get_user_agent(request)

    user = db.query(User).filter(User.email == login_in.email).first()
    if not user:
        record_audit_log(
            db=db,
            action="LOGIN_FAILED_USER_NOT_FOUND",
            resource_type="AUTH",
            status_code=status.HTTP_401_UNAUTHORIZED,
            ip_address=ip,
            user_agent=ua,
            details={"attempted_email": login_in.email},
        )
        # Use generic error message to prevent username enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password against stored Argon2id hash
    if not verify_password(login_in.password, user.hashed_password):
        record_audit_log(
            db=db,
            action="LOGIN_FAILED_PASSWORD_MISMATCH",
            resource_type="AUTH",
            resource_id=user.id,
            user_id=user.id,
            status_code=status.HTTP_401_UNAUTHORIZED,
            ip_address=ip,
            user_agent=ua,
            details={"email": user.email},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        record_audit_log(
            db=db,
            action="LOGIN_FAILED_ACCOUNT_INACTIVE",
            resource_type="AUTH",
            resource_id=user.id,
            user_id=user.id,
            status_code=status.HTTP_403_FORBIDDEN,
            ip_address=ip,
            user_agent=ua,
            details={"email": user.email},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact platform administrator.",
        )

    # Update last login timestamp
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    # Generate JWT access token
    token, expires_in = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
    )

    # Record login audit log
    record_audit_log(
        db=db,
        action="LOGIN_SUCCESS",
        resource_type="AUTH",
        resource_id=user.id,
        user_id=user.id,
        status_code=status.HTTP_200_OK,
        ip_address=ip,
        user_agent=ua,
        details={"role": user.role},
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user profile",
)
def get_me(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Return the profile of the currently authenticated user."""
    return current_user


# RBAC Verification Endpoints
@router.get(
    "/test/admin-only",
    status_code=status.HTTP_200_OK,
    summary="Verify Admin RBAC guard",
    include_in_schema=False,
)
def test_admin_only(
    current_user: User = Depends(require_admin),
) -> dict:
    return {
        "message": "Admin access granted",
        "user_id": current_user.id,
        "role": current_user.role,
    }


@router.get(
    "/test/analyst-only",
    status_code=status.HTTP_200_OK,
    summary="Verify Analyst RBAC guard",
    include_in_schema=False,
)
def test_analyst_only(
    current_user: User = Depends(require_analyst),
) -> dict:
    return {
        "message": "Analyst access granted",
        "user_id": current_user.id,
        "role": current_user.role,
    }


@router.get(
    "/test/viewer-only",
    status_code=status.HTTP_200_OK,
    summary="Verify Viewer RBAC guard",
    include_in_schema=False,
)
def test_viewer_only(
    current_user: User = Depends(require_viewer),
) -> dict:
    return {
        "message": "Viewer access granted",
        "user_id": current_user.id,
        "role": current_user.role,
    }
