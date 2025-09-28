"""
PostgreSQL user repository implementation.
Handles user data access operations using SQLAlchemy with async support.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.orm import selectinload

from core.domain.user import User
from core.domain.role import Role
from core.ports.user_repository import UserRepository
from core.ports.logger import Logger
from core.ports.exceptions import RepositoryError
from ..models import User as UserModel, Role as RoleModel, UserRole as UserRoleModel


class PostgresUserRepository(UserRepository):
    """
    PostgreSQL implementation of the user repository interface.
    """

    def __init__(self, session: AsyncSession, logger: Logger):
        """
        Initialize PostgreSQL user repository.

        Args:
            session: SQLAlchemy async session
            logger: Logger instance
        """
        self.session = session
        self.logger = logger

    async def save(self, user: User) -> User:
        """
        Save a user to the repository.

        Args:
            user: User entity to save

        Returns:
            Saved user entity with updated fields
        """
        try:
            self.logger.debug("Saving user", user_id=str(user.id))

            # Create or update user model
            user_model = UserModel(
                id=user.id,
                email=user.email,
                password_hash=user.password_hash,
                first_name=user.first_name,
                last_name=user.last_name,
                profile_photo_filename=user.profile_photo_filename,
                is_active=user.is_active,
                created_at=user.created_at,
                updated_at=user.updated_at
            )

            self.session.add(user_model)
            # Don't commit here - let the caller handle the transaction
            # await self.session.commit()
            # await self.session.refresh(user_model)

            return self._model_to_entity(user_model)

        except Exception as e:
            # Don't rollback here either - let the caller handle it
            # await self.session.rollback()
            self.logger.error("Save user error", error=str(e), user_id=str(user.id))
            raise RepositoryError(f"Failed to save user: {str(e)}")

    async def find_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Find a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            User entity if found, None otherwise
        """
        try:
            self.logger.debug("Finding user by ID", user_id=str(user_id))

            result = await self.session.execute(
                select(UserModel)
                .options(selectinload(UserModel.user_roles).selectinload(UserRoleModel.role))
                .where(UserModel.id == user_id)
            )
            user_model = result.scalar_one_or_none()

            if user_model:
                return self._model_to_entity(user_model)

            return None

        except Exception as e:
            self.logger.error("Find user by ID error", error=str(e), user_id=str(user_id))
            raise RepositoryError(f"Failed to find user: {str(e)}")

    async def find_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by their email address.

        Args:
            email: User's email address

        Returns:
            User entity if found, None otherwise
        """
        try:
            self.logger.debug("Finding user by email", email=email)

            result = await self.session.execute(
                select(UserModel)
                .options(selectinload(UserModel.user_roles).selectinload(UserRoleModel.role))
                .where(UserModel.email == email)
            )
            user_model = result.scalar_one_or_none()

            if user_model:
                return self._model_to_entity(user_model)

            return None

        except Exception as e:
            self.logger.error("Find user by email error", error=str(e), email=email)
            raise RepositoryError(f"Failed to find user by email: {str(e)}")

    async def find_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Find all users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        try:
            self.logger.debug("Finding all users", skip=skip, limit=limit)

            result = await self.session.execute(
                select(UserModel)
                .options(selectinload(UserModel.user_roles).selectinload(UserRoleModel.role))
                .offset(skip)
                .limit(limit)
            )
            user_models = result.scalars().all()

            return [self._model_to_entity(model) for model in user_models]

        except Exception as e:
            self.logger.error("Find all users error", error=str(e))
            raise RepositoryError(f"Failed to find users: {str(e)}")

    async def find_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Find all active users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of active user entities
        """
        try:
            self.logger.debug("Finding active users", skip=skip, limit=limit)

            result = await self.session.execute(
                select(UserModel)
                .options(selectinload(UserModel.user_roles).selectinload(UserRoleModel.role))
                .where(UserModel.is_active == True)
                .offset(skip)
                .limit(limit)
            )
            user_models = result.scalars().all()

            return [self._model_to_entity(model) for model in user_models]

        except Exception as e:
            self.logger.error("Find active users error", error=str(e))
            raise RepositoryError(f"Failed to find active users: {str(e)}")

    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user exists with the given email.

        Args:
            email: Email address to check

        Returns:
            True if user exists, False otherwise
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(UserModel).where(UserModel.email == email)
            )
            count = result.scalar()
            return count > 0

        except Exception as e:
            self.logger.error("Check user exists by email error", error=str(e), email=email)
            return False

    async def exists_by_id(self, user_id: UUID) -> bool:
        """
        Check if a user exists with the given ID.

        Args:
            user_id: User ID to check

        Returns:
            True if user exists, False otherwise
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(UserModel).where(UserModel.id == user_id)
            )
            count = result.scalar()
            return count > 0

        except Exception as e:
            self.logger.error("Check user exists by ID error", error=str(e), user_id=str(user_id))
            return False

    async def update(self, user: User) -> User:
        """
        Update an existing user.

        Args:
            user: User entity with updated data

        Returns:
            Updated user entity
        """
        try:
            self.logger.debug("Updating user", user_id=str(user.id))

            # Update user in database
            await self.session.execute(
                update(UserModel)
                .where(UserModel.id == user.id)
                .values(
                    email=user.email,
                    password_hash=user.password_hash,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    profile_photo_filename=user.profile_photo_filename,
                    is_active=user.is_active,
                    updated_at=user.updated_at
                )
            )
            await self.session.commit()

            # Return updated user
            return await self.find_by_id(user.id) or user

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Update user error", error=str(e), user_id=str(user.id))
            raise RepositoryError(f"Failed to update user: {str(e)}")

    async def delete(self, user_id: UUID) -> bool:
        """
        Delete a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was deleted, False if not found
        """
        try:
            self.logger.debug("Deleting user", user_id=str(user_id))

            result = await self.session.execute(
                delete(UserModel).where(UserModel.id == user_id)
            )
            await self.session.commit()

            return result.rowcount > 0

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Delete user error", error=str(e), user_id=str(user_id))
            raise RepositoryError(f"Failed to delete user: {str(e)}")

    async def count(self) -> int:
        """
        Count total number of users.

        Returns:
            Total number of users
        """
        try:
            result = await self.session.execute(
                select(func.count()).select_from(UserModel)
            )
            return result.scalar() or 0

        except Exception as e:
            self.logger.error("Count users error", error=str(e))
            raise RepositoryError(f"Failed to count users: {str(e)}")

    async def count_active(self) -> int:
        """
        Count total number of active users.

        Returns:
            Total number of active users
        """
        try:
            result = await self.session.execute(
                select(func.count())
                .select_from(UserModel)
                .where(UserModel.is_active == True)
            )
            return result.scalar() or 0

        except Exception as e:
            self.logger.error("Count active users error", error=str(e))
            raise RepositoryError(f"Failed to count active users: {str(e)}")

    async def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> bool:
        """
        Assign a role to a user.

        Args:
            user_id: User's unique identifier
            role_id: Role's unique identifier

        Returns:
            True if assignment was successful, False otherwise
        """
        try:
            self.logger.debug("Assigning role to user", user_id=str(user_id), role_id=str(role_id))

            # Check if assignment already exists
            existing = await self.session.execute(
                select(UserRoleModel).where(
                    and_(
                        UserRoleModel.user_id == user_id,
                        UserRoleModel.role_id == role_id
                    )
                )
            )

            if existing.scalar_one_or_none():
                return False  # Already assigned

            # Create new assignment
            user_role = UserRoleModel(user_id=user_id, role_id=role_id)
            self.session.add(user_role)
            await self.session.commit()

            return True

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Assign role to user error", error=str(e), user_id=str(user_id), role_id=str(role_id))
            raise RepositoryError(f"Failed to assign role to user: {str(e)}")

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> bool:
        """
        Remove a role from a user.

        Args:
            user_id: User's unique identifier
            role_id: Role's unique identifier

        Returns:
            True if removal was successful, False otherwise
        """
        try:
            self.logger.debug("Removing role from user", user_id=str(user_id), role_id=str(role_id))

            result = await self.session.execute(
                delete(UserRoleModel).where(
                    and_(
                        UserRoleModel.user_id == user_id,
                        UserRoleModel.role_id == role_id
                    )
                )
            )
            await self.session.commit()

            return result.rowcount > 0

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Remove role from user error", error=str(e), user_id=str(user_id), role_id=str(role_id))
            raise RepositoryError(f"Failed to remove role from user: {str(e)}")

    async def get_user_roles(self, user_id: UUID) -> List[dict]:
        """
        Get all roles assigned to a user.

        Args:
            user_id: User's unique identifier

        Returns:
            List of role dictionaries
        """
        try:
            self.logger.debug("Getting user roles", user_id=str(user_id))

            result = await self.session.execute(
                select(RoleModel)
                .join(UserRoleModel)
                .where(UserRoleModel.user_id == user_id)
            )
            role_models = result.scalars().all()

            return [
                {
                    "id": str(role.id),
                    "name": role.name,
                    "description": role.description
                }
                for role in role_models
            ]

        except Exception as e:
            self.logger.error("Get user roles error", error=str(e), user_id=str(user_id))
            raise RepositoryError(f"Failed to get user roles: {str(e)}")

    async def get_users_by_role(self, role_id: UUID, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users assigned to a specific role.

        Args:
            role_id: Role's unique identifier
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        try:
            self.logger.debug("Getting users by role", role_id=str(role_id), skip=skip, limit=limit)

            result = await self.session.execute(
                select(UserModel)
                .join(UserRoleModel)
                .where(UserRoleModel.role_id == role_id)
                .offset(skip)
                .limit(limit)
            )
            user_models = result.scalars().all()

            return [self._model_to_entity(model) for model in user_models]

        except Exception as e:
            self.logger.error("Get users by role error", error=str(e), role_id=str(role_id))
            raise RepositoryError(f"Failed to get users by role: {str(e)}")

    def _model_to_entity(self, user_model: UserModel) -> User:
        """
        Convert database model to domain entity.

        Args:
            user_model: Database model instance

        Returns:
            User domain entity
        """
        # Create user entity
        user = User(
            id=user_model.id,
            email=user_model.email,
            password_hash=user_model.password_hash,
            first_name=user_model.first_name,
            last_name=user_model.last_name,
            profile_photo_filename=user_model.profile_photo_filename,
            is_active=user_model.is_active,
            created_at=user_model.created_at,
            updated_at=user_model.updated_at
        )

        # Assign roles to user entity
        if user_model.user_roles:
            for user_role in user_model.user_roles:
                if user_role.role:
                    # Convert role model to domain entity
                    role = Role(
                        id=user_role.role.id,
                        name=user_role.role.name,
                        description=user_role.role.description,
                        created_at=user_role.role.created_at
                    )
                    user.assign_role(role)

        return user
