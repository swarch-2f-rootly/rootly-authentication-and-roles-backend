"""
PostgreSQL role repository implementation.
Handles role data access operations using SQLAlchemy with async support.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.orm import selectinload

from core.domain.role import Role
from core.ports.role_repository import RoleRepository
from core.ports.logger import Logger
from core.ports.exceptions import RepositoryError
from ..models import Role as RoleModel, Permission as PermissionModel, RolePermission as RolePermissionModel


class PostgresRoleRepository(RoleRepository):
    """
    PostgreSQL implementation of the role repository interface.
    """

    def __init__(self, session: AsyncSession, logger: Logger):
        """
        Initialize PostgreSQL role repository.

        Args:
            session: SQLAlchemy async session
            logger: Logger instance
        """
        self.session = session
        self.logger = logger

    async def save(self, role: Role) -> Role:
        """
        Save a role to the repository.

        Args:
            role: Role entity to save

        Returns:
            Saved role entity with updated fields
        """
        try:
            self.logger.debug("Saving role", role_id=str(role.id))

            # Create or update role model
            role_model = RoleModel(
                id=role.id,
                name=role.name,
                description=role.description,
                created_at=role.created_at
            )

            self.session.add(role_model)
            await self.session.commit()
            await self.session.refresh(role_model)

            return self._model_to_entity(role_model)

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Save role error", error=str(e), role_id=str(role.id))
            raise RepositoryError(f"Failed to save role: {str(e)}")

    async def find_by_id(self, role_id: UUID) -> Optional[Role]:
        """
        Find a role by its ID.

        Args:
            role_id: Role's unique identifier

        Returns:
            Role entity if found, None otherwise
        """
        try:
            self.logger.debug("Finding role by ID", role_id=str(role_id))

            result = await self.session.execute(
                select(RoleModel)
                .options(selectinload(RoleModel.role_permissions).selectinload(RolePermissionModel.permission))
                .where(RoleModel.id == role_id)
            )
            role_model = result.scalar_one_or_none()

            if role_model:
                return self._model_to_entity(role_model)

            return None

        except Exception as e:
            self.logger.error("Find role by ID error", error=str(e), role_id=str(role_id))
            raise RepositoryError(f"Failed to find role: {str(e)}")

    async def find_by_name(self, name: str) -> Optional[Role]:
        """
        Find a role by its name.

        Args:
            name: Role name

        Returns:
            Role entity if found, None otherwise
        """
        try:
            self.logger.debug("Finding role by name", role_name=name)

            result = await self.session.execute(
                select(RoleModel)
                .options(selectinload(RoleModel.role_permissions).selectinload(RolePermissionModel.permission))
                .where(RoleModel.name == name)
            )
            role_model = result.scalar_one_or_none()

            if role_model:
                return self._model_to_entity(role_model)

            return None

        except Exception as e:
            self.logger.error("Find role by name error", error=str(e), role_name=name)
            raise RepositoryError(f"Failed to find role: {str(e)}")

    async def find_all(self, skip: int = 0, limit: int = 100) -> List[Role]:
        """
        Find all roles with pagination.

        Args:
            skip: Number of roles to skip
            limit: Maximum number of roles to return

        Returns:
            List of role entities
        """
        try:
            self.logger.debug("Finding all roles", skip=skip, limit=limit)

            result = await self.session.execute(
                select(RoleModel)
                .options(selectinload(RoleModel.role_permissions).selectinload(RolePermissionModel.permission))
                .offset(skip)
                .limit(limit)
            )
            role_models = result.scalars().all()

            return [self._model_to_entity(role_model) for role_model in role_models]

        except Exception as e:
            self.logger.error("Find all roles error", error=str(e))
            raise RepositoryError(f"Failed to find roles: {str(e)}")

    async def exists_by_name(self, name: str) -> bool:
        """
        Check if a role exists with the given name.

        Args:
            name: Role name to check

        Returns:
            True if role exists, False otherwise
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(RoleModel).where(RoleModel.name == name)
            )
            count = result.scalar()
            return count > 0

        except Exception as e:
            self.logger.error("Exists by name error", error=str(e), role_name=name)
            raise RepositoryError(f"Failed to check role existence: {str(e)}")

    async def exists_by_id(self, role_id: UUID) -> bool:
        """
        Check if a role exists with the given ID.

        Args:
            role_id: Role ID to check

        Returns:
            True if role exists, False otherwise
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(RoleModel).where(RoleModel.id == role_id)
            )
            count = result.scalar()
            return count > 0

        except Exception as e:
            self.logger.error("Exists by ID error", error=str(e), role_id=str(role_id))
            raise RepositoryError(f"Failed to check role existence: {str(e)}")

    async def update(self, role: Role) -> Role:
        """
        Update an existing role.

        Args:
            role: Role entity with updated data

        Returns:
            Updated role entity
        """
        try:
            self.logger.debug("Updating role", role_id=str(role.id))

            # Update role model
            update_data = {
                "name": role.name,
                "description": role.description,
                "updated_at": func.now()
            }

            await self.session.execute(
                update(RoleModel)
                .where(RoleModel.id == role.id)
                .values(**update_data)
            )
            await self.session.commit()

            # Fetch updated role
            return await self.find_by_id(role.id)

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Update role error", error=str(e), role_id=str(role.id))
            raise RepositoryError(f"Failed to update role: {str(e)}")

    async def delete(self, role_id: UUID) -> bool:
        """
        Delete a role by its ID.

        Args:
            role_id: Role's unique identifier

        Returns:
            True if role was deleted, False if not found
        """
        try:
            self.logger.debug("Deleting role", role_id=str(role_id))

            result = await self.session.execute(
                delete(RoleModel).where(RoleModel.id == role_id)
            )
            await self.session.commit()

            deleted_count = result.rowcount
            return deleted_count > 0

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Delete role error", error=str(e), role_id=str(role_id))
            raise RepositoryError(f"Failed to delete role: {str(e)}")

    async def count(self) -> int:
        """
        Count total number of roles.

        Returns:
            Total number of roles
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(RoleModel)
            )
            return result.scalar()

        except Exception as e:
            self.logger.error("Count roles error", error=str(e))
            raise RepositoryError(f"Failed to count roles: {str(e)}")

    async def assign_permission_to_role(self, role_id: UUID, permission_id: UUID) -> bool:
        """
        Assign a permission to a role.

        Args:
            role_id: Role's unique identifier
            permission_id: Permission's unique identifier

        Returns:
            True if assignment was successful, False otherwise
        """
        try:
            self.logger.debug("Assigning permission to role",
                            role_id=str(role_id), permission_id=str(permission_id))

            # Check if assignment already exists
            result = await self.session.execute(
                select(func.count()).select_from(RolePermissionModel).where(
                    and_(
                        RolePermissionModel.role_id == role_id,
                        RolePermissionModel.permission_id == permission_id
                    )
                )
            )
            if result.scalar() > 0:
                return True  # Already assigned

            # Create new assignment
            role_permission = RolePermissionModel(
                role_id=role_id,
                permission_id=permission_id
            )

            self.session.add(role_permission)
            await self.session.commit()

            return True

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Assign permission to role error", error=str(e),
                            role_id=str(role_id), permission_id=str(permission_id))
            raise RepositoryError(f"Failed to assign permission to role: {str(e)}")

    async def remove_permission_from_role(self, role_id: UUID, permission_id: UUID) -> bool:
        """
        Remove a permission from a role.

        Args:
            role_id: Role's unique identifier
            permission_id: Permission's unique identifier

        Returns:
            True if removal was successful, False otherwise
        """
        try:
            self.logger.debug("Removing permission from role",
                            role_id=str(role_id), permission_id=str(permission_id))

            result = await self.session.execute(
                delete(RolePermissionModel).where(
                    and_(
                        RolePermissionModel.role_id == role_id,
                        RolePermissionModel.permission_id == permission_id
                    )
                )
            )
            await self.session.commit()

            deleted_count = result.rowcount
            return deleted_count > 0

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Remove permission from role error", error=str(e),
                            role_id=str(role_id), permission_id=str(permission_id))
            raise RepositoryError(f"Failed to remove permission from role: {str(e)}")

    async def get_role_permissions(self, role_id: UUID) -> List[dict]:
        """
        Get all permissions assigned to a role.

        Args:
            role_id: Role's unique identifier

        Returns:
            List of permission dictionaries
        """
        try:
            self.logger.debug("Getting role permissions", role_id=str(role_id))

            result = await self.session.execute(
                select(PermissionModel)
                .join(RolePermissionModel)
                .where(RolePermissionModel.role_id == role_id)
            )
            permission_models = result.scalars().all()

            return [permission_model.to_dict() for permission_model in permission_models]

        except Exception as e:
            self.logger.error("Get role permissions error", error=str(e), role_id=str(role_id))
            raise RepositoryError(f"Failed to get role permissions: {str(e)}")

    async def get_roles_by_permission(self, permission_id: UUID, skip: int = 0, limit: int = 100) -> List[Role]:
        """
        Get all roles that have a specific permission.

        Args:
            permission_id: Permission's unique identifier
            skip: Number of roles to skip
            limit: Maximum number of roles to return

        Returns:
            List of role entities
        """
        try:
            self.logger.debug("Getting roles by permission",
                            permission_id=str(permission_id), skip=skip, limit=limit)

            result = await self.session.execute(
                select(RoleModel)
                .join(RolePermissionModel)
                .where(RolePermissionModel.permission_id == permission_id)
                .options(selectinload(RoleModel.role_permissions).selectinload(RolePermissionModel.permission))
                .offset(skip)
                .limit(limit)
            )
            role_models = result.scalars().all()

            return [self._model_to_entity(role_model) for role_model in role_models]

        except Exception as e:
            self.logger.error("Get roles by permission error", error=str(e),
                            permission_id=str(permission_id))
            raise RepositoryError(f"Failed to get roles by permission: {str(e)}")

    def _model_to_entity(self, role_model: RoleModel) -> Role:
        """
        Convert RoleModel to Role entity.

        Args:
            role_model: SQLAlchemy role model

        Returns:
            Role domain entity
        """
        from core.domain.role import Role

        # Extract permissions
        permissions = []
        if role_model.role_permissions:
            for rp in role_model.role_permissions:
                if rp.permission:
                    permissions.append({
                        "id": str(rp.permission.id),
                        "name": rp.permission.name,
                        "resource": rp.permission.resource,
                        "action": rp.permission.action,
                        "scope": rp.permission.scope
                    })

        return Role(
            id=role_model.id,
            name=role_model.name,
            description=role_model.description,
            permissions=permissions,
            created_at=role_model.created_at
        )
