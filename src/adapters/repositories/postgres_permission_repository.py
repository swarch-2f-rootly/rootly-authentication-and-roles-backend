"""
PostgreSQL permission repository implementation.
Handles permission data access operations using SQLAlchemy with async support.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.orm import selectinload

from core.domain.permission import Permission
from core.ports.permission_repository import PermissionRepository
from core.ports.logger import Logger
from core.ports.exceptions import RepositoryError
from ..models import Permission as PermissionModel, Role as RoleModel, RolePermission as RolePermissionModel


class PostgresPermissionRepository(PermissionRepository):
    """
    PostgreSQL implementation of the permission repository interface.
    """

    def __init__(self, session: AsyncSession, logger: Logger):
        """
        Initialize PostgreSQL permission repository.

        Args:
            session: SQLAlchemy async session
            logger: Logger instance
        """
        self.session = session
        self.logger = logger

    async def save(self, permission: Permission) -> Permission:
        """
        Save a permission to the repository.

        Args:
            permission: Permission entity to save

        Returns:
            Saved permission entity with updated fields
        """
        try:
            self.logger.debug("Saving permission", permission_id=str(permission.id))

            # Create or update permission model
            permission_model = PermissionModel(
                id=permission.id,
                name=permission.name,
                resource=permission.resource,
                action=permission.action,
                scope=permission.scope,
                created_at=permission.created_at
            )

            self.session.add(permission_model)
            await self.session.commit()
            await self.session.refresh(permission_model)

            return self._model_to_entity(permission_model)

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Save permission error", error=str(e), permission_id=str(permission.id))
            raise RepositoryError(f"Failed to save permission: {str(e)}")

    async def find_by_id(self, permission_id: UUID) -> Optional[Permission]:
        """
        Find a permission by its ID.

        Args:
            permission_id: Permission's unique identifier

        Returns:
            Permission entity if found, None otherwise
        """
        try:
            self.logger.debug("Finding permission by ID", permission_id=str(permission_id))

            result = await self.session.execute(
                select(PermissionModel)
                .options(selectinload(PermissionModel.role_permissions).selectinload(RolePermissionModel.role))
                .where(PermissionModel.id == permission_id)
            )
            permission_model = result.scalar_one_or_none()

            if permission_model:
                return self._model_to_entity(permission_model)

            return None

        except Exception as e:
            self.logger.error("Find permission by ID error", error=str(e), permission_id=str(permission_id))
            raise RepositoryError(f"Failed to find permission: {str(e)}")

    async def find_by_name(self, name: str) -> Optional[Permission]:
        """
        Find a permission by its name.

        Args:
            name: Permission name

        Returns:
            Permission entity if found, None otherwise
        """
        try:
            self.logger.debug("Finding permission by name", permission_name=name)

            result = await self.session.execute(
                select(PermissionModel)
                .options(selectinload(PermissionModel.role_permissions).selectinload(RolePermissionModel.role))
                .where(PermissionModel.name == name)
            )
            permission_model = result.scalar_one_or_none()

            if permission_model:
                return self._model_to_entity(permission_model)

            return None

        except Exception as e:
            self.logger.error("Find permission by name error", error=str(e), permission_name=name)
            raise RepositoryError(f"Failed to find permission: {str(e)}")

    async def find_by_resource(self, resource: str) -> List[Permission]:
        """
        Find all permissions for a specific resource.

        Args:
            resource: Resource name

        Returns:
            List of permission entities for the resource
        """
        try:
            self.logger.debug("Finding permissions by resource", resource=resource)

            result = await self.session.execute(
                select(PermissionModel)
                .options(selectinload(PermissionModel.role_permissions).selectinload(RolePermissionModel.role))
                .where(PermissionModel.resource == resource)
            )
            permission_models = result.scalars().all()

            return [self._model_to_entity(permission_model) for permission_model in permission_models]

        except Exception as e:
            self.logger.error("Find permissions by resource error", error=str(e), resource=resource)
            raise RepositoryError(f"Failed to find permissions by resource: {str(e)}")

    async def find_by_resource_and_action(self, resource: str, action: str) -> List[Permission]:
        """
        Find permissions by resource and action.

        Args:
            resource: Resource name
            action: HTTP action (GET, POST, PUT, DELETE)

        Returns:
            List of permission entities
        """
        try:
            self.logger.debug("Finding permissions by resource and action",
                            resource=resource, action=action)

            result = await self.session.execute(
                select(PermissionModel)
                .options(selectinload(PermissionModel.role_permissions).selectinload(RolePermissionModel.role))
                .where(
                    and_(
                        PermissionModel.resource == resource,
                        PermissionModel.action == action
                    )
                )
            )
            permission_models = result.scalars().all()

            return [self._model_to_entity(permission_model) for permission_model in permission_models]

        except Exception as e:
            self.logger.error("Find permissions by resource and action error",
                            error=str(e), resource=resource, action=action)
            raise RepositoryError(f"Failed to find permissions by resource and action: {str(e)}")

    async def find_all(self, skip: int = 0, limit: int = 100) -> List[Permission]:
        """
        Find all permissions with pagination.

        Args:
            skip: Number of permissions to skip
            limit: Maximum number of permissions to return

        Returns:
            List of permission entities
        """
        try:
            self.logger.debug("Finding all permissions", skip=skip, limit=limit)

            result = await self.session.execute(
                select(PermissionModel)
                .options(selectinload(PermissionModel.role_permissions).selectinload(RolePermissionModel.role))
                .offset(skip)
                .limit(limit)
            )
            permission_models = result.scalars().all()

            return [self._model_to_entity(permission_model) for permission_model in permission_models]

        except Exception as e:
            self.logger.error("Find all permissions error", error=str(e))
            raise RepositoryError(f"Failed to find permissions: {str(e)}")

    async def exists_by_name(self, name: str) -> bool:
        """
        Check if a permission exists with the given name.

        Args:
            name: Permission name to check

        Returns:
            True if permission exists, False otherwise
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(PermissionModel).where(PermissionModel.name == name)
            )
            count = result.scalar()
            return count > 0

        except Exception as e:
            self.logger.error("Exists by name error", error=str(e), permission_name=name)
            raise RepositoryError(f"Failed to check permission existence: {str(e)}")

    async def exists_by_id(self, permission_id: UUID) -> bool:
        """
        Check if a permission exists with the given ID.

        Args:
            permission_id: Permission ID to check

        Returns:
            True if permission exists, False otherwise
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(PermissionModel).where(PermissionModel.id == permission_id)
            )
            count = result.scalar()
            return count > 0

        except Exception as e:
            self.logger.error("Exists by ID error", error=str(e), permission_id=str(permission_id))
            raise RepositoryError(f"Failed to check permission existence: {str(e)}")

    async def update(self, permission: Permission) -> Permission:
        """
        Update an existing permission.

        Args:
            permission: Permission entity with updated data

        Returns:
            Updated permission entity
        """
        try:
            self.logger.debug("Updating permission", permission_id=str(permission.id))

            # Update permission model
            update_data = {
                "name": permission.name,
                "resource": permission.resource,
                "action": permission.action,
                "scope": permission.scope,
                "updated_at": func.now()
            }

            await self.session.execute(
                update(PermissionModel)
                .where(PermissionModel.id == permission.id)
                .values(**update_data)
            )
            await self.session.commit()

            # Fetch updated permission
            return await self.find_by_id(permission.id)

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Update permission error", error=str(e), permission_id=str(permission.id))
            raise RepositoryError(f"Failed to update permission: {str(e)}")

    async def delete(self, permission_id: UUID) -> bool:
        """
        Delete a permission by its ID.

        Args:
            permission_id: Permission's unique identifier

        Returns:
            True if permission was deleted, False if not found
        """
        try:
            self.logger.debug("Deleting permission", permission_id=str(permission_id))

            result = await self.session.execute(
                delete(PermissionModel).where(PermissionModel.id == permission_id)
            )
            await self.session.commit()

            deleted_count = result.rowcount
            return deleted_count > 0

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Delete permission error", error=str(e), permission_id=str(permission_id))
            raise RepositoryError(f"Failed to delete permission: {str(e)}")

    async def count(self) -> int:
        """
        Count total number of permissions.

        Returns:
            Total number of permissions
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(PermissionModel)
            )
            return result.scalar()

        except Exception as e:
            self.logger.error("Count permissions error", error=str(e))
            raise RepositoryError(f"Failed to count permissions: {str(e)}")

    async def count_by_resource(self, resource: str) -> int:
        """
        Count permissions by resource.

        Args:
            resource: Resource name

        Returns:
            Number of permissions for the resource
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(PermissionModel).where(PermissionModel.resource == resource)
            )
            return result.scalar()

        except Exception as e:
            self.logger.error("Count permissions by resource error", error=str(e), resource=resource)
            raise RepositoryError(f"Failed to count permissions by resource: {str(e)}")

    def _model_to_entity(self, permission_model: PermissionModel) -> Permission:
        """
        Convert PermissionModel to Permission entity.

        Args:
            permission_model: SQLAlchemy permission model

        Returns:
            Permission domain entity
        """
        from core.domain.permission import Permission

        # Extract roles that have this permission
        roles = []
        if permission_model.role_permissions:
            for rp in permission_model.role_permissions:
                if rp.role:
                    roles.append({
                        "id": str(rp.role.id),
                        "name": rp.role.name,
                        "description": rp.role.description
                    })

        return Permission(
            id=permission_model.id,
            name=permission_model.name,
            resource=permission_model.resource,
            action=permission_model.action,
            scope=permission_model.scope,
            roles=roles,
            created_at=permission_model.created_at
        )
