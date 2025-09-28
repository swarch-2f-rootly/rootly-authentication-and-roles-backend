"""
Seed service for automatic database data initialization.
Handles creation of initial roles, permissions, and admin user.
"""

from typing import List, Dict, Any, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from ..domain.user import User as UserEntity
from ..ports.logger import Logger
from ..ports.user_repository import UserRepository
from .password_service import PasswordService
from config.settings import get_settings


class SeedService:
    """Service for seeding initial database data."""

    def __init__(self, logger: Logger):
        """
        Initialize seed service.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.settings = get_settings()

    async def _get_session(self) -> AsyncSession:
        """Get database session."""
        engine = create_async_engine(self.settings.database.url)
        session_factory = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        return session_factory()

    async def check_seed_needed(self) -> bool:
        """
        Check if seeding is needed by looking for existing data.

        Returns:
            True if seeding is needed, False otherwise
        """
        try:
            from adapters.models.role import Role
            from adapters.models.permission import Permission
            
            session = await self._get_session()
            
            try:
                # Check if roles exist
                result = await session.execute(select(Role))
                roles = result.scalars().all()
                
                # Check if permissions exist
                result = await session.execute(select(Permission))
                permissions = result.scalars().all()
                
                # If no roles or permissions, we need seeding
                needs_seed = len(roles) == 0 or len(permissions) == 0
                
                if needs_seed:
                    self.logger.info("Database seeding needed - no roles or permissions found")
                else:
                    self.logger.info("Database already seeded - roles and permissions exist")
                
                return needs_seed
                
            finally:
                await session.close()
                
        except Exception as e:
            self.logger.error(f"Failed to check seed status: {str(e)}")
            return True  # Assume seeding is needed on error

    async def create_permissions(self, session: AsyncSession) -> List[Any]:
        """
        Create initial permissions.

        Args:
            session: Database session

        Returns:
            List of created permission objects
        """
        from adapters.models.permission import Permission
        
        self.logger.info("Creating initial permissions...")

        permissions_data = [
            # User permissions
            {"name": "users:read:own", "resource": "users", "action": "GET", "scope": "own"},
            {"name": "users:read:all", "resource": "users", "action": "GET", "scope": "all"},
            {"name": "users:create:all", "resource": "users", "action": "POST", "scope": "all"},
            {"name": "users:update:own", "resource": "users", "action": "PUT", "scope": "own"},
            {"name": "users:update:all", "resource": "users", "action": "PUT", "scope": "all"},
            {"name": "users:delete:own", "resource": "users", "action": "DELETE", "scope": "own"},
            {"name": "users:delete:all", "resource": "users", "action": "DELETE", "scope": "all"},

            # Analytics permissions
            {"name": "analytics:read:all", "resource": "analytics", "action": "GET", "scope": "all"},
            {"name": "analytics:export:all", "resource": "analytics", "action": "POST", "scope": "all"},

            # Sensor permissions
            {"name": "sensors:read:all", "resource": "sensors", "action": "GET", "scope": "all"},
            {"name": "sensors:update:all", "resource": "sensors", "action": "PUT", "scope": "all"},
            {"name": "sensors:create:all", "resource": "sensors", "action": "POST", "scope": "all"},
            {"name": "sensors:delete:all", "resource": "sensors", "action": "DELETE", "scope": "all"},

            # Role permissions
            {"name": "roles:read:all", "resource": "roles", "action": "GET", "scope": "all"},
            {"name": "roles:create:all", "resource": "roles", "action": "POST", "scope": "all"},
            {"name": "roles:update:all", "resource": "roles", "action": "PUT", "scope": "all"},
            {"name": "roles:delete:all", "resource": "roles", "action": "DELETE", "scope": "all"},

            # Permission permissions
            {"name": "permissions:read:all", "resource": "permissions", "action": "GET", "scope": "all"},
            {"name": "permissions:create:all", "resource": "permissions", "action": "POST", "scope": "all"},
            {"name": "permissions:update:all", "resource": "permissions", "action": "PUT", "scope": "all"},
            {"name": "permissions:delete:all", "resource": "permissions", "action": "DELETE", "scope": "all"},

            # System permissions
            {"name": "system:admin:get", "resource": "system", "action": "GET", "scope": "all"},
            {"name": "system:admin:post", "resource": "system", "action": "POST", "scope": "all"},
            {"name": "system:admin:put", "resource": "system", "action": "PUT", "scope": "all"},
            {"name": "system:admin:delete", "resource": "system", "action": "DELETE", "scope": "all"},

            # Reports permissions
            {"name": "reports:admin:all", "resource": "reports", "action": "GET", "scope": "all"},
        ]

        permissions = []
        for perm_data in permissions_data:
            # Check if permission already exists
            result = await session.execute(
                select(Permission).where(Permission.name == perm_data["name"])
            )
            existing = result.scalar_one_or_none()
            
            if not existing:
                permission = Permission(**perm_data)
                session.add(permission)
                permissions.append(permission)

        await session.commit()
        self.logger.info(f"Created {len(permissions)} permissions")
        return permissions

    async def create_roles_and_assign_permissions(self, session: AsyncSession, permissions: List[Any]) -> List[Any]:
        """
        Create initial roles and assign permissions.

        Args:
            session: Database session
            permissions: List of permission objects

        Returns:
            List of created role objects
        """
        from adapters.models.role import Role
        from adapters.models.role_permission import RolePermission
        
        self.logger.info("Creating initial roles...")

        roles_data = [
            {
                "name": "farmer",
                "description": "Basic user role for farmers",
                "permissions": ["users:read:own", "users:update:own", "users:delete:own", 
                               "analytics:read:all", "sensors:read:all"]
            },
            {
                "name": "technician",
                "description": "Technician role with sensor management capabilities",
                "permissions": ["users:read:own", "users:update:own", "users:delete:own",
                               "analytics:read:all", "sensors:read:all", "sensors:update:all", 
                               "sensors:create:all", "analytics:export:all"]
            },
            {
                "name": "manager",
                "description": "Manager role with user and reporting capabilities",
                "permissions": ["users:read:all", "users:create:all", "users:update:all",
                               "analytics:read:all", "sensors:read:all", "sensors:update:all",
                               "sensors:create:all", "analytics:export:all", "reports:admin:all"]
            },
            {
                "name": "admin",
                "description": "Administrator role with full system access",
                "permissions": ["users:read:all", "users:create:all", "users:update:all", 
                               "users:delete:all", "analytics:read:all", "sensors:read:all",
                               "sensors:update:all", "sensors:create:all", "sensors:delete:all",
                               "roles:read:all", "roles:create:all", "roles:update:all", 
                               "roles:delete:all", "permissions:read:all", "permissions:create:all",
                               "permissions:update:all", "permissions:delete:all", 
                               "system:admin:get", "system:admin:post", "system:admin:put", 
                               "system:admin:delete", "analytics:export:all", "reports:admin:all"]
            }
        ]

        # Create a permission lookup for faster access
        permission_lookup = {perm.name: perm for perm in permissions}

        roles = []
        for role_data in roles_data:
            # Check if role already exists
            result = await session.execute(
                select(Role).where(Role.name == role_data["name"])
            )
            existing_role = result.scalar_one_or_none()
            
            if existing_role:
                self.logger.info(f"Role {role_data['name']} already exists, skipping")
                roles.append(existing_role)
                continue

            # Create role
            role = Role(
                name=role_data["name"],
                description=role_data["description"]
            )
            session.add(role)
            await session.commit()  # Commit to get role ID
            
            # Assign permissions to role
            for perm_name in role_data["permissions"]:
                permission = permission_lookup.get(perm_name)
                if permission:
                    # Check if role-permission assignment already exists
                    result = await session.execute(
                        select(RolePermission).where(
                            RolePermission.role_id == role.id,
                            RolePermission.permission_id == permission.id
                        )
                    )
                    existing_assignment = result.scalar_one_or_none()
                    
                    if not existing_assignment:
                        role_permission = RolePermission(role_id=role.id, permission_id=permission.id)
                        session.add(role_permission)
                else:
                    self.logger.warning(f"Permission {perm_name} not found for role {role_data['name']}")

            await session.commit()
            roles.append(role)

        self.logger.info(f"Created/verified {len(roles)} roles")
        return roles

    async def create_admin_user(self, session: AsyncSession) -> Optional[Any]:
        """
        Create default admin user.

        Args:
            session: Database session

        Returns:
            Created admin user or None if failed
        """
        from adapters.models.user import User
        from adapters.models.role import Role
        from adapters.models.user_role import UserRole
        
        try:
            self.logger.info("Creating default admin user...")

            # Check if admin user already exists
            result = await session.execute(
                select(User).where(User.email == "admin@rootly.com")
            )
            existing_admin = result.scalar_one_or_none()

            if existing_admin:
                self.logger.info("Admin user already exists")
                return existing_admin

            # Get admin role
            result = await session.execute(
                select(Role).where(Role.name == "admin")
            )
            admin_role = result.scalar_one_or_none()

            if not admin_role:
                self.logger.error("Admin role not found")
                return None

            # Create admin user
            password_service = PasswordService(self.logger)
            admin_password = "Admin123!"  # Default password - should be changed in production
            hashed_password = await password_service.hash_password(admin_password)

            admin_user = User(
                email="admin@rootly.com",
                password_hash=hashed_password,
                first_name="System",
                last_name="Administrator"
            )

            session.add(admin_user)
            await session.commit()
            await session.refresh(admin_user)

            # Assign admin role
            user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
            session.add(user_role)
            await session.commit()

            self.logger.info("Default admin user created successfully")
            self.logger.info("Email: admin@rootly.com")
            self.logger.info("Password: Admin123!")
            self.logger.warning("⚠️  Please change the default password immediately!")

            return admin_user

        except Exception as e:
            await session.rollback()
            self.logger.error(f"Failed to create admin user: {str(e)}")
            return None

    async def seed_database(self) -> bool:
        """
        Seed the database with initial data.

        Returns:
            True if seeding was successful, False otherwise
        """
        try:
            self.logger.info("Starting database seeding...")

            # Check if seeding is needed
            if not await self.check_seed_needed():
                self.logger.info("Database seeding not needed")
                return True

            session = await self._get_session()
            
            try:
                # Create permissions
                permissions = await self.create_permissions(session)

                # Re-fetch all permissions for role assignment
                from adapters.models.permission import Permission
                result = await session.execute(select(Permission))
                all_permissions = result.scalars().all()

                # Create roles and assign permissions
                roles = await self.create_roles_and_assign_permissions(session, all_permissions)

                # Create admin user
                admin_user = await self.create_admin_user(session)
                if not admin_user:
                    self.logger.error("Failed to create admin user")
                    return False

                self.logger.info("Database seeding completed successfully!")
                self.logger.info("=" * 50)
                self.logger.info("Default Admin User Created:")
                self.logger.info("Email: admin@rootly.com")
                self.logger.info("Password: Admin123!")
                self.logger.warning("⚠️  Remember to change default password in production!")
                self.logger.info("=" * 50)

                return True

            finally:
                await session.close()

        except Exception as e:
            self.logger.error(f"Database seeding failed: {str(e)}")
            return False

    async def create_test_users(self) -> bool:
        """
        Create additional test users for development.

        Returns:
            True if test users were created successfully, False otherwise
        """
        try:
            self.logger.info("Creating test users...")

            session = await self._get_session()
            
            try:
                from adapters.models.user import User
                from adapters.models.role import Role
                from adapters.models.user_role import UserRole

                test_users_data = [
                    {
                        "email": "farmer@rootly.com",
                        "password": "Farmer123!",
                        "first_name": "Juan",
                        "last_name": "Farmer",
                        "role": "farmer"
                    },
                    {
                        "email": "tech@rootly.com",
                        "password": "Tech123!",
                        "first_name": "Maria",
                        "last_name": "Technician",
                        "role": "technician"
                    },
                    {
                        "email": "manager@rootly.com",
                        "password": "Manager123!",
                        "first_name": "Carlos",
                        "last_name": "Manager",
                        "role": "manager"
                    }
                ]

                password_service = PasswordService(self.logger)
                created_users = []

                for user_data in test_users_data:
                    # Check if user already exists
                    result = await session.execute(
                        select(User).where(User.email == user_data["email"])
                    )
                    existing_user = result.scalar_one_or_none()

                    if existing_user:
                        self.logger.info(f"Test user {user_data['email']} already exists")
                        continue

                    # Get role
                    result = await session.execute(
                        select(Role).where(Role.name == user_data["role"])
                    )
                    role = result.scalar_one_or_none()

                    if not role:
                        self.logger.warning(f"Role {user_data['role']} not found, skipping user {user_data['email']}")
                        continue

                    # Create user
                    hashed_password = await password_service.hash_password(user_data["password"])

                    user = User(
                        email=user_data["email"],
                        password_hash=hashed_password,
                        first_name=user_data["first_name"],
                        last_name=user_data["last_name"]
                    )

                    session.add(user)
                    await session.commit()
                    await session.refresh(user)

                    # Assign role
                    user_role = UserRole(user_id=user.id, role_id=role.id)
                    session.add(user_role)
                    await session.commit()

                    created_users.append(user_data)
                    self.logger.info(f"Created test user: {user_data['email']}")

                if created_users:
                    self.logger.info("Test users created successfully:")
                    for user in created_users:
                        self.logger.info(f"  - {user['email']}: {user['password']} (Role: {user['role']})")

                return True

            finally:
                await session.close()

        except Exception as e:
            self.logger.error(f"Failed to create test users: {str(e)}")
            return False
