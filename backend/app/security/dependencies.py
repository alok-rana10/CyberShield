"""FastAPI authentication and RBAC dependency guards."""

from typing import Callable, List
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.security.jwt import decode_access_token
from app.utils.audit_helper import record_audit_log, get_client_ip, get_user_agent

bearer_scheme = HTTPBearer(auto_error=False)

# Hierarchy: admin has all privileges; analyst has analyst and viewer; viewer has viewer
ROLE_HIERARCHY = {
    "admin": {"admin", "analyst", "viewer"},
    "analyst": {"analyst", "viewer"},
    "viewer": {"viewer"},
}


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate Bearer JWT and return authenticated User."""
    ip = get_client_ip(request)
    ua = get_user_agent(request)

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id: str | None = payload.get("sub")
        if not user_id:
            record_audit_log(
                db=db,
                action="AUTH_TOKEN_INVALID",
                resource_type="AUTH",
                status_code=status.HTTP_401_UNAUTHORIZED,
                ip_address=ip,
                user_agent=ua,
                details={"reason": "Missing subject claim in token"},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        record_audit_log(
            db=db,
            action="AUTH_TOKEN_EXPIRED",
            resource_type="AUTH",
            status_code=status.HTTP_401_UNAUTHORIZED,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Token has expired"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        record_audit_log(
            db=db,
            action="AUTH_TOKEN_INVALID",
            resource_type="AUTH",
            status_code=status.HTTP_401_UNAUTHORIZED,
            ip_address=ip,
            user_agent=ua,
            details={"reason": "Invalid token signature or structure"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        record_audit_log(
            db=db,
            action="AUTH_USER_NOT_FOUND",
            resource_type="AUTH",
            status_code=status.HTTP_401_UNAUTHORIZED,
            ip_address=ip,
            user_agent=ua,
            details={"attempted_user_id": user_id},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the authenticated user account is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account.",
        )
    return current_user


def require_roles(allowed_roles: List[str]) -> Callable:
    """Enforce Role-Based Access Control (RBAC) dependency factory."""

    async def role_checker(
        request: Request,
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db),
    ) -> User:
        user_effective_roles = ROLE_HIERARCHY.get(current_user.role, set())
        has_permission = any(role in user_effective_roles for role in allowed_roles)

        if not has_permission:
            ip = get_client_ip(request)
            ua = get_user_agent(request)
            record_audit_log(
                db=db,
                action="AUTHORIZATION_DENIED",
                resource_type="RBAC",
                status_code=status.HTTP_403_FORBIDDEN,
                ip_address=ip,
                user_id=current_user.id,
                user_agent=ua,
                details={
                    "user_role": current_user.role,
                    "required_roles": allowed_roles,
                    "endpoint": str(request.url.path),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation.",
            )
        return current_user

    return role_checker


# Convenient role dependency shortcuts
require_admin = require_roles(["admin"])
require_analyst = require_roles(["analyst", "admin"])
require_viewer = require_roles(["viewer", "analyst", "admin"])
