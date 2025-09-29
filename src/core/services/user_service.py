"""
User service implementation.
Handles user management operations including CRUD and role assignments.
"""

from typing import List, Optional
from uuid import UUID

from ..domain.user import User
from ..ports.user_service import UserService as UserServiceInterface
from ..ports.user_repository import UserRepository
from ..ports.role_repository import RoleRepository
from ..ports.logger import Logger
from ..ports.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    RoleNotFoundError,
    ValidationError,
    InvalidCredentialsError,
    PasswordTooWeakError
)
from .password_service import PasswordService


class UserService(UserServiceInterface):
    """
    User service implementation for managing user accounts and profiles.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        password_service: PasswordService,
        logger: Logger
    ):
        """
        Initialize user service.

        Args:
            user_repository: User repository instance
            role_repository: Role repository instance
            password_service: Password service instance
            logger: Logger instance
        """
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.password_service = password_service
        self.logger = logger

    async def create_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str
    ) -> User:
        """
        Create a new user account.

        Args:
            email: User's email address
            password: User's password (will be hashed)
            first_name: User's first name
            last_name: User's last name

        Returns:
            Created user entity

        Raises:
            UserAlreadyExistsError: If email already exists
            PasswordTooWeakError: If password doesn't meet requirements
            ValidationError: If input data is invalid

        Note:
            Profile photos should be managed through dedicated file upload endpoints,
            not through user creation.
        """
        self.logger.info("Creating new user", email=email)

        try:
            # Check if user already exists
            existing_user = await self.user_repository.find_by_email(email)
            if existing_user:
                self.logger.warn("User creation failed: email already exists", email=email)
                raise UserAlreadyExistsError("Email address is already registered")

            # Validate password strength
            self.password_service.validate_password_strength(password)

            # Hash password
            password_hash = await self.password_service.hash_password(password)

            # Create user entity
            user = User(
                email=email,
                password_hash=password_hash,
                first_name=first_name,
                last_name=last_name
            )

            # Save user
            saved_user = await self.user_repository.save(user)

            self.logger.info("User created successfully", user_id=str(saved_user.id))
            return saved_user

        except (UserAlreadyExistsError, ValidationError):
            raise
        except Exception as e:
            self.logger.error("User creation error", error=str(e), email=email)
            raise ValidationError("Failed to create user account")

    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Get a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            User entity if found, None otherwise
        """
        try:
            self.logger.debug("Starting get_user_by_id", user_id=str(user_id))

            user = await self.user_repository.find_by_id(user_id)
            self.logger.debug("Repository find_by_id returned", user_found=user is not None, user_id=str(user_id))

            if user:
                self.logger.debug("User found, loading roles", user_id=str(user_id), user_email=user.email)
                # Load user roles
                user_roles = await self.user_repository.get_user_roles(user_id)
                self.logger.debug("User roles loaded", user_id=str(user_id), roles_count=len(user_roles) if user_roles else 0)
                # Note: In a full implementation, you'd populate the user's roles here
            else:
                self.logger.debug("User not found in repository", user_id=str(user_id))

            self.logger.debug("get_user_by_id completed", user_id=str(user_id), success=user is not None)
            return user

        except Exception as e:
            self.logger.error("Get user by ID error", error=str(e), error_type=type(e).__name__, user_id=str(user_id), traceback=__import__('traceback').format_exc())
            return None

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by their email address.

        Args:
            email: User's email address

        Returns:
            User entity if found, None otherwise
        """
        try:
            return await self.user_repository.find_by_email(email)

        except Exception as e:
            self.logger.error("Get user by email error", error=str(e), email=email)
            return None

    async def get_all_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        try:
            return await self.user_repository.find_all(skip, limit)

        except Exception as e:
            self.logger.error("Get all users error", error=str(e))
            return []

    async def update_user_profile(
        self,
        user_id: UUID,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None
    ) -> User:
        """
        Update a user's profile information.

        Args:
            user_id: User's unique identifier
            first_name: New first name
            last_name: New last name

        Returns:
            Updated user entity

        Raises:
            UserNotFoundError: If user doesn't exist
            ValidationError: If input data is invalid

        Note:
            Profile photos should be managed through dedicated file upload endpoints,
            not through this general profile update method.
        """
        self.logger.info("Updating user profile", user_id=str(user_id), first_name=first_name, last_name=last_name)

        try:
            # Get existing user
            user = await self.user_repository.find_by_id(user_id)
            if not user:
                self.logger.warn("User not found for profile update", user_id=str(user_id))
                raise UserNotFoundError("User not found")

            self.logger.debug("User found for update", user_id=str(user_id), current_first_name=user.first_name, current_last_name=user.last_name)

            # Update user profile
            user.update_profile(
                first_name=first_name,
                last_name=last_name
            )

            # Save updated user
            updated_user = await self.user_repository.update(user)

            self.logger.info("User profile updated successfully", user_id=str(user_id), new_first_name=first_name, new_last_name=last_name)
            return updated_user

        except UserNotFoundError:
            raise
        except Exception as e:
            self.logger.error("Update user profile error", error=str(e), error_type=type(e).__name__, user_id=str(user_id), traceback=__import__('traceback').format_exc())
            raise ValidationError("Failed to update user profile")

    async def update_user_profile_photo_filename(
        self,
        user_id: UUID,
        profile_photo_filename: Optional[str]
    ) -> User:
        """
        Update a user's profile photo filename.

        This method should only be used by file upload endpoints,
        not by general user profile update operations.

        Args:
            user_id: User's unique identifier
            profile_photo_filename: New profile photo filename (or None to remove)

        Returns:
            Updated user entity

        Raises:
            UserNotFoundError: If user doesn't exist
        """
        self.logger.info("Updating user profile photo filename", user_id=str(user_id))

        try:
            # Get existing user
            user = await self.user_repository.find_by_id(user_id)
            if not user:
                raise UserNotFoundError("User not found")

            # Update profile photo filename
            user.update_profile(
                profile_photo_filename=profile_photo_filename
            )

            # Save updated user
            updated_user = await self.user_repository.update(user)

            self.logger.info("User profile photo filename updated successfully", user_id=str(user_id))
            return updated_user

        except UserNotFoundError:
            raise
        except Exception as e:
            self.logger.error("Update user profile photo filename error", error=str(e), user_id=str(user_id))
            raise

    async def change_user_password(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change a user's password.

        Args:
            user_id: User's unique identifier
            current_password: Current password for verification
            new_password: New password

        Returns:
            True if password was changed successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            InvalidCredentialsError: If current password is wrong
            PasswordTooWeakError: If new password doesn't meet requirements
        """
        self.logger.info("Changing user password", user_id=str(user_id))

        try:
            # Get user
            user = await self.user_repository.find_by_id(user_id)
            if not user:
                raise UserNotFoundError("User not found")

            # Verify current password
            password_valid = await self.password_service.verify_password(
                current_password, user.password_hash
            )

            if not password_valid:
                raise InvalidCredentialsError("Current password is incorrect")

            # Validate new password strength
            await self.password_service.validate_password_strength(new_password)

            # Hash new password
            new_password_hash = await self.password_service.hash_password(new_password)

            # Update user password
            user.change_password(new_password_hash)

            # Save updated user
            await self.user_repository.update(user)

            self.logger.info("User password changed successfully", user_id=str(user_id))
            return True

        except (UserNotFoundError, InvalidCredentialsError, ValidationError):
            raise
        except Exception as e:
            self.logger.error("Change password error", error=str(e), user_id=str(user_id))
            return False

    async def delete_user(self, user_id: UUID) -> bool:
        """
        Delete a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was deleted, False if not found
        """
        self.logger.info("Deleting user", user_id=str(user_id))

        try:
            result = await self.user_repository.delete(user_id)

            if result:
                self.logger.info("User deleted successfully", user_id=str(user_id))
            else:
                self.logger.warn("User deletion failed: user not found", user_id=str(user_id))

            return result

        except Exception as e:
            self.logger.error("Delete user error", error=str(e), user_id=str(user_id))
            return False

    async def activate_user(self, user_id: UUID) -> bool:
        """
        Activate a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was activated, False if not found or already active
        """
        try:
            user = await self.user_repository.find_by_id(user_id)
            if not user:
                return False

            if user.is_active:
                return False  # Already active

            user.activate()
            await self.user_repository.update(user)

            self.logger.info("User activated", user_id=str(user_id))
            return True

        except Exception as e:
            self.logger.error("Activate user error", error=str(e), user_id=str(user_id))
            return False

    async def deactivate_user(self, user_id: UUID) -> bool:
        """
        Deactivate a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was deactivated, False if not found or already inactive
        """
        try:
            user = await self.user_repository.find_by_id(user_id)
            if not user:
                return False

            if not user.is_active:
                return False  # Already inactive

            user.deactivate()
            await self.user_repository.update(user)

            self.logger.info("User deactivated", user_id=str(user_id))
            return True

        except Exception as e:
            self.logger.error("Deactivate user error", error=str(e), user_id=str(user_id))
            return False

    async def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> bool:
        """
        Assign a role to a user.

        Args:
            user_id: User's unique identifier
            role_id: Role's unique identifier

        Returns:
            True if role was assigned successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            RoleNotFoundError: If role doesn't exist
        """
        self.logger.info("Assigning role to user", user_id=str(user_id), role_id=str(role_id))

        try:
            # Verify user exists
            user_exists = await self.user_repository.exists_by_id(user_id)
            if not user_exists:
                raise UserNotFoundError("User not found")

            # Verify role exists
            role_exists = await self.role_repository.exists_by_id(role_id)
            if not role_exists:
                raise RoleNotFoundError("Role not found")

            # Assign role
            result = await self.user_repository.assign_role_to_user(user_id, role_id)

            if result:
                self.logger.info("Role assigned to user successfully", user_id=str(user_id), role_id=str(role_id))
            else:
                self.logger.warn("Role assignment failed", user_id=str(user_id), role_id=str(role_id))

            return result

        except (UserNotFoundError, RoleNotFoundError):
            raise
        except Exception as e:
            self.logger.error("Assign role error", error=str(e), user_id=str(user_id), role_id=str(role_id))
            return False

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> bool:
        """
        Remove a role from a user.

        Args:
            user_id: User's unique identifier
            role_id: Role's unique identifier

        Returns:
            True if role was removed successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            RoleNotFoundError: If role doesn't exist
        """
        self.logger.info("Removing role from user", user_id=str(user_id), role_id=str(role_id))

        try:
            # Verify user exists
            user_exists = await self.user_repository.exists_by_id(user_id)
            if not user_exists:
                raise UserNotFoundError("User not found")

            # Verify role exists
            role_exists = await self.role_repository.exists_by_id(role_id)
            if not role_exists:
                raise RoleNotFoundError("Role not found")

            # Remove role
            result = await self.user_repository.remove_role_from_user(user_id, role_id)

            if result:
                self.logger.info("Role removed from user successfully", user_id=str(user_id), role_id=str(role_id))
            else:
                self.logger.warn("Role removal failed", user_id=str(user_id), role_id=str(role_id))

            return result

        except (UserNotFoundError, RoleNotFoundError):
            raise
        except Exception as e:
            self.logger.error("Remove role error", error=str(e), user_id=str(user_id), role_id=str(role_id))
            return False

    async def get_user_roles(self, user_id: UUID) -> List[dict]:
        """
        Get all roles assigned to a user.

        Args:
            user_id: User's unique identifier

        Returns:
            List of role dictionaries
        """
        try:
            return await self.user_repository.get_user_roles(user_id)

        except Exception as e:
            self.logger.error("Get user roles error", error=str(e), user_id=str(user_id))
            return []

    async def get_users_with_role(self, role_id: UUID, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users that have a specific role.

        Args:
            role_id: Role's unique identifier
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        try:
            return await self.user_repository.get_users_by_role(role_id, skip, limit)

        except Exception as e:
            self.logger.error("Get users with role error", error=str(e), role_id=str(role_id))
            return []

    async def count_users(self) -> int:
        """
        Count total number of users.

        Returns:
            Total number of users
        """
        try:
            return await self.user_repository.count()

        except Exception as e:
            self.logger.error("Count users error", error=str(e))
            return 0

    async def count_active_users(self) -> int:
        """
        Count total number of active users.

        Returns:
            Total number of active users
        """
        try:
            return await self.user_repository.count_active()

        except Exception as e:
            self.logger.error("Count active users error", error=str(e))
            return 0

    async def change_password(self, user_id: UUID, current_password: str, new_password: str) -> bool:
        """
        Change user password after validating current password.

        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password

        Returns:
            True if password changed successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            InvalidCredentialsError: If current password is wrong
            PasswordTooWeakError: If new password doesn't meet requirements
        """
        try:
            # Get user
            user = await self.user_repository.find_by_id(user_id)
            if not user:
                raise UserNotFoundError(f"User {user_id} not found")

            # Verify current password
            if not await self.password_service.verify_password(current_password, user.password_hash):
                raise InvalidCredentialsError("Current password is incorrect")

            # Validate new password strength
            self.password_service.validate_password_strength(new_password)

            # Hash new password
            new_password_hash = await self.password_service.hash_password(new_password)

            # Update user
            user.password_hash = new_password_hash
            await self.user_repository.save(user)

            self.logger.info("Password changed successfully", user_id=str(user_id))
            return True

        except (UserNotFoundError, InvalidCredentialsError, PasswordTooWeakError):
            raise
        except Exception as e:
            self.logger.error("Change password error", error=str(e), user_id=str(user_id))
            return False

    async def list_users(self, skip: int = 0, limit: int = 10) -> List[User]:
        """
        List users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of users
        """
        try:
            return await self.user_repository.find_all(skip=skip, limit=limit)

        except Exception as e:
            self.logger.error("List users error", error=str(e))
            return []
