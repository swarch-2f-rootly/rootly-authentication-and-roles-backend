"""
Role management FastAPI route handlers.
Handles role and permission management endpoints.
"""

from uuid import UUID
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.ports.role_repository import RoleRepository
from core.ports.permission_repository import PermissionRepository
from core.ports.logger import Logger
from core.ports.exceptions import (
    RoleNotFoundError,
    ValidationError
)
from .models import (
    RoleResponse,
    RoleListResponse,
    PermissionResponse,
    PermissionListResponse,
    ErrorResponse
)
from .dependencies import get_role_repository, get_permission_repository, get_logger, get_db_session
from .auth_handlers import get_current_user_required

router = APIRouter(prefix="/api/v1/roles", tags=["role-management"])


async def get_role_repository_dependency(session: AsyncSession = Depends(get_db_session)) -> RoleRepository:
    """Dependency injection for role repository."""
    return await get_role_repository(session)


async def get_permission_repository_dependency(session: AsyncSession = Depends(get_db_session)) -> PermissionRepository:
    """Dependency injection for permission repository."""
    return await get_permission_repository(session)


@router.get("", response_model=RoleListResponse)
async def list_roles(
    current_user: dict = Depends(get_current_user_required),
    role_repo: RoleRepository = Depends(get_role_repository_dependency),
    permission_repo: PermissionRepository = Depends(get_permission_repository_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    List all available roles and their permissions.

    Returns roles with their associated permissions for role-based access control.
    """
    try:
        logger.info("Listing all roles", requester_id=current_user.get('id'))

        # Get all roles
        roles = await role_repo.find_all()
        total = await role_repo.count()

        role_responses = []
        for role in roles:
            # Get permissions for this role
            permissions = await role_repo.get_role_permissions(role.id)
            permission_count = len(permissions)

            role_responses.append(RoleResponse(
                id=role.id,
                name=role.name,
                description=role.description,
                permissions=permissions,
                permission_count=permission_count,
                created_at=role.created_at
            ))

        response = RoleListResponse(
            roles=role_responses,
            total=total
        )

        logger.info("Roles listed successfully", count=len(role_responses), total=total)
        return response

    except Exception as e:
        logger.error("List roles error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to list roles",
                "timestamp": "Exception"
            }
        )


@router.get("/permissions", response_model=PermissionListResponse)
async def list_permissions(
    current_user: dict = Depends(get_current_user_required),
    permission_repo: PermissionRepository = Depends(get_permission_repository_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    List all available permissions.

    Returns all permissions in the system for reference.
    """
    try:
        logger.info("Listing all permissions", requester_id=current_user.get('id'))

        # Get all permissions
        permissions = await permission_repo.find_all()
        total = await permission_repo.count()

        permission_responses = []
        for permission in permissions:
            permission_responses.append(PermissionResponse(
                id=permission.id,
                name=permission.name,
                resource=permission.resource,
                action=permission.action,
                scope=permission.scope,
                full_name=getattr(permission, 'full_name', f"{permission.resource}:{permission.action}:{permission.scope}"),
                created_at=permission.created_at
            ))

        response = PermissionListResponse(
            permissions=permission_responses,
            total=total
        )

        logger.info("Permissions listed successfully", count=len(permission_responses), total=total)
        return response

    except Exception as e:
        logger.error("List permissions error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to list permissions",
                "timestamp": "Exception"
            }
        )


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    role_repo: RoleRepository = Depends(get_role_repository_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Get a specific role with its permissions.

    Args:
        role_id: UUID of the role to retrieve
    """
    try:
        logger.info("Getting role details", role_id=str(role_id), requester_id=current_user.get('id'))

        # Get role
        role = await role_repo.find_by_id(role_id)
        if not role:
            raise RoleNotFoundError(f"Role with ID {role_id} not found")

        # Get permissions for this role
        permissions = await role_repo.get_role_permissions(role.id)
        permission_count = len(permissions)

        response = RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            permissions=permissions,
            permission_count=permission_count,
            created_at=role.created_at
        )

        logger.info("Role details retrieved successfully", role_id=str(role_id))
        return response

    except RoleNotFoundError as e:
        logger.warn("Role not found", role_id=str(role_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "ROLE_NOT_FOUND",
                "message": str(e),
                "timestamp": "RoleNotFoundError"
            }
        )
    except Exception as e:
        logger.error("Get role error", error=str(e), role_id=str(role_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to retrieve role",
                "timestamp": "Exception"
            }
        )


@router.get("/permissions/{permission_id}", response_model=PermissionResponse)
async def get_permission(
    permission_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    permission_repo: PermissionRepository = Depends(get_permission_repository_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Get a specific permission details.

    Args:
        permission_id: UUID of the permission to retrieve
    """
    try:
        logger.info("Getting permission details", permission_id=str(permission_id), requester_id=current_user.get('id'))

        # Get permission
        permission = await permission_repo.find_by_id(permission_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "PERMISSION_NOT_FOUND",
                    "message": f"Permission with ID {permission_id} not found",
                    "timestamp": "Exception"
                }
            )

        response = PermissionResponse(
            id=permission.id,
            name=permission.name,
            resource=permission.resource,
            action=permission.action,
            scope=permission.scope,
            full_name=getattr(permission, 'full_name', f"{permission.resource}:{permission.action}:{permission.scope}"),
            created_at=permission.created_at
        )

        logger.info("Permission details retrieved successfully", permission_id=str(permission_id))
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Get permission error", error=str(e), permission_id=str(permission_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to retrieve permission",
                "timestamp": "Exception"
            }
        )
