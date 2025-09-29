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
        logger.info("Starting role listing process", requester_id=current_user.get('id'))

        # Get all roles
        logger.debug("Retrieving all roles from repository")
        roles = await role_repo.find_all()
        logger.debug("Roles retrieved from repository", role_count=len(roles))

        logger.debug("Counting total roles")
        total = await role_repo.count()
        logger.debug("Total roles counted", total=total)

        role_responses = []
        for role in roles:
            logger.debug("Processing role permissions", role_id=str(role.id), role_name=role.name)
            # Get permissions for this role
            permissions = await role_repo.get_role_permissions(role.id)
            permission_count = len(permissions)
            logger.debug("Role permissions retrieved", role_id=str(role.id), permission_count=permission_count)

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

        logger.info("Roles listed successfully", count=len(role_responses), total=total, requester_id=current_user.get('id'))
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
        logger.info("Starting permission listing process", requester_id=current_user.get('id'))

        # Get all permissions
        logger.debug("Retrieving all permissions from repository")
        permissions = await permission_repo.find_all()
        logger.debug("Permissions retrieved from repository", permission_count=len(permissions))

        logger.debug("Counting total permissions")
        total = await permission_repo.count()
        logger.debug("Total permissions counted", total=total)

        permission_responses = []
        for permission in permissions:
            full_name = getattr(permission, 'full_name', f"{permission.resource}:{permission.action}:{permission.scope}")
            logger.debug("Processing permission", permission_id=str(permission.id), permission_name=permission.name, full_name=full_name)

            permission_responses.append(PermissionResponse(
                id=permission.id,
                name=permission.name,
                resource=permission.resource,
                action=permission.action,
                scope=permission.scope,
                full_name=full_name,
                created_at=permission.created_at
            ))

        response = PermissionListResponse(
            permissions=permission_responses,
            total=total
        )

        logger.info("Permissions listed successfully", count=len(permission_responses), total=total, requester_id=current_user.get('id'))
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
        logger.info("Starting role retrieval process", role_id=str(role_id), requester_id=current_user.get('id'))

        # Get role
        logger.debug("Retrieving role from repository", role_id=str(role_id))
        role = await role_repo.find_by_id(role_id)
        if not role:
            logger.warn("Role not found in repository", role_id=str(role_id))
            raise RoleNotFoundError(f"Role with ID {role_id} not found")

        logger.debug("Role found", role_id=str(role.id), role_name=role.name)

        # Get permissions for this role
        logger.debug("Retrieving role permissions", role_id=str(role.id))
        permissions = await role_repo.get_role_permissions(role.id)
        permission_count = len(permissions)
        logger.debug("Role permissions retrieved", role_id=str(role.id), permission_count=permission_count)

        response = RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            permissions=permissions,
            permission_count=permission_count,
            created_at=role.created_at
        )

        logger.info("Role details retrieved successfully", role_id=str(role_id), role_name=role.name, permission_count=permission_count, requester_id=current_user.get('id'))
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
        logger.info("Starting permission retrieval process", permission_id=str(permission_id), requester_id=current_user.get('id'))

        # Get permission
        logger.debug("Retrieving permission from repository", permission_id=str(permission_id))
        permission = await permission_repo.find_by_id(permission_id)
        if not permission:
            logger.warn("Permission not found in repository", permission_id=str(permission_id))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "PERMISSION_NOT_FOUND",
                    "message": f"Permission with ID {permission_id} not found",
                    "timestamp": "Exception"
                }
            )

        full_name = getattr(permission, 'full_name', f"{permission.resource}:{permission.action}:{permission.scope}")
        logger.debug("Permission found", permission_id=str(permission.id), permission_name=permission.name, full_name=full_name)

        response = PermissionResponse(
            id=permission.id,
            name=permission.name,
            resource=permission.resource,
            action=permission.action,
            scope=permission.scope,
            full_name=full_name,
            created_at=permission.created_at
        )

        logger.info("Permission details retrieved successfully", permission_id=str(permission_id), permission_name=permission.name, full_name=full_name, requester_id=current_user.get('id'))
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
