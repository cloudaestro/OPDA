"""
Core Pydantic data models for Okta entities.

Represents users, groups, applications, roles, and related entities
with comprehensive validation and type safety.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class UserStatus(str, Enum):
    """Okta user status enumeration."""

    ACTIVE = "ACTIVE"
    DEPROVISIONED = "DEPROVISIONED"
    LOCKED_OUT = "LOCKED_OUT"
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    PROVISIONED = "PROVISIONED"
    RECOVERY = "RECOVERY"
    STAGED = "STAGED"
    SUSPENDED = "SUSPENDED"


class GroupType(str, Enum):
    """Okta group type enumeration."""

    OKTA_GROUP = "OKTA_GROUP"
    AD_GROUP = "AD_GROUP"
    LDAP_GROUP = "LDAP_GROUP"
    APP_GROUP = "APP_GROUP"


class AppStatus(str, Enum):
    """Okta application status enumeration."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class OktaProfile(BaseModel):
    """Base Okta profile information."""

    login: str | None = Field(default=None, description="User login name")
    email: str | None = Field(default=None, description="Primary email address")
    first_name: str | None = Field(
        default=None, alias="firstName", description="First name"
    )
    last_name: str | None = Field(
        default=None, alias="lastName", description="Last name"
    )
    display_name: str | None = Field(
        default=None, alias="displayName", description="Display name"
    )
    mobile_phone: str | None = Field(
        default=None, alias="mobilePhone", description="Mobile phone number"
    )
    employee_number: str | None = Field(
        default=None, alias="employeeNumber", description="Employee ID"
    )
    cost_center: str | None = Field(
        default=None, alias="costCenter", description="Cost center"
    )
    organization: str | None = Field(
        default=None, description="Organization"
    )
    division: str | None = Field(default=None, description="Division")
    department: str | None = Field(default=None, description="Department")
    manager: str | None = Field(default=None, description="Manager ID")
    manager_id: str | None = Field(
        default=None, alias="managerId", description="Manager user ID"
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str | None) -> str | None:
        """Basic email validation."""
        if v and "@" not in v:
            raise ValueError("Invalid email format")
        return v


class OktaUser(BaseModel):
    """Okta user entity with comprehensive profile information."""

    id: str = Field(..., description="Unique Okta user ID")
    status: UserStatus = Field(..., description="Current user status")
    created: datetime = Field(..., description="User creation timestamp")
    activated: datetime | None = Field(
        default=None, description="User activation timestamp"
    )
    status_changed: datetime | None = Field(
        default=None, alias="statusChanged", description="Last status change timestamp"
    )
    last_login: datetime | None = Field(
        default=None, alias="lastLogin", description="Last login timestamp"
    )
    last_updated: datetime | None = Field(
        default=None, alias="lastUpdated", description="Last update timestamp"
    )
    password_changed: datetime | None = Field(
        default=None, alias="passwordChanged", description="Last password change"
    )
    profile: OktaProfile = Field(..., description="User profile information")

    # Derived fields for audit analysis
    groups: list[str] = Field(
        default_factory=list, description="List of group IDs user belongs to"
    )
    roles: list[str] = Field(
        default_factory=list, description="List of role IDs assigned to user"
    )
    applications: list[str] = Field(
        default_factory=list, description="List of app IDs user has access to"
    )

    @field_validator("id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        """Validate Okta user ID format."""
        if not v or len(v) < 10:
            raise ValueError("Invalid Okta user ID")
        return v

    def is_active(self) -> bool:
        """Check if user is in active status."""
        return self.status == UserStatus.ACTIVE

    def days_since_last_login(self) -> int | None:
        """Calculate days since last login."""
        if not self.last_login:
            return None
        return (datetime.utcnow() - self.last_login).days

    def is_stale_account(self, days_threshold: int = 90) -> bool:
        """Check if account is stale based on last login."""
        days_since_login = self.days_since_last_login()
        return days_since_login is not None and days_since_login > days_threshold


class OktaGroup(BaseModel):
    """Okta group entity with membership information."""

    id: str = Field(..., description="Unique Okta group ID")
    created: datetime = Field(..., description="Group creation timestamp")
    last_updated: datetime | None = Field(
        default=None, alias="lastUpdated", description="Last update timestamp"
    )
    last_membership_updated: datetime | None = Field(
        default=None,
        alias="lastMembershipUpdated",
        description="Last membership change timestamp"
    )
    object_class: list[str] = Field(
        default_factory=list, alias="objectClass", description="Object class list"
    )
    type: GroupType = Field(..., description="Group type")

    # Profile information
    name: str = Field(..., description="Group name")
    description: str | None = Field(default=None, description="Group description")

    # Member information
    members: list[str] = Field(
        default_factory=list, description="List of user IDs in this group"
    )

    @field_validator("name")
    @classmethod
    def validate_group_name(cls, v: str) -> str:
        """Validate group name is not empty."""
        if not v.strip():
            raise ValueError("Group name cannot be empty")
        return v.strip()

    def member_count(self) -> int:
        """Get the number of members in this group."""
        return len(self.members)

    def is_privileged_group(self) -> bool:
        """Check if this is a privileged/admin group based on naming patterns."""
        privileged_patterns = [
            "admin", "administrator", "superuser", "root", "system",
            "elevated", "privileged", "super", "domain", "enterprise"
        ]
        name_lower = self.name.lower()
        return any(pattern in name_lower for pattern in privileged_patterns)


class OktaApplication(BaseModel):
    """Okta application entity with access information."""

    id: str = Field(..., description="Unique Okta application ID")
    name: str = Field(..., description="Application name")
    label: str = Field(..., description="Application display label")
    status: AppStatus = Field(..., description="Application status")
    created: datetime = Field(..., description="Application creation timestamp")
    last_updated: datetime | None = Field(
        default=None, alias="lastUpdated", description="Last update timestamp"
    )

    # Application settings
    sign_on_mode: str | None = Field(
        default=None, alias="signOnMode", description="SSO sign-on mode"
    )
    features: list[str] = Field(
        default_factory=list, description="Enabled application features"
    )

    # Access information
    assigned_users: list[str] = Field(
        default_factory=list, description="List of user IDs with access"
    )
    assigned_groups: list[str] = Field(
        default_factory=list, description="List of group IDs with access"
    )

    @field_validator("name", "label")
    @classmethod
    def validate_name_fields(cls, v: str) -> str:
        """Validate name and label fields are not empty."""
        if not v.strip():
            raise ValueError("Name and label fields cannot be empty")
        return v.strip()

    def is_active(self) -> bool:
        """Check if application is active."""
        return self.status == AppStatus.ACTIVE

    def total_assignments(self) -> int:
        """Get total number of user and group assignments."""
        return len(self.assigned_users) + len(self.assigned_groups)

    def is_high_privilege_app(self) -> bool:
        """Check if this is a high-privilege application."""
        high_priv_patterns = [
            "admin", "console", "aws", "azure", "gcp", "database", "prod",
            "production", "financial", "hr", "payroll", "sso", "identity"
        ]
        app_name_lower = self.name.lower()
        app_label_lower = self.label.lower()
        return any(
            pattern in app_name_lower or pattern in app_label_lower
            for pattern in high_priv_patterns
        )


class OktaRole(BaseModel):
    """Okta role entity representing administrative roles."""

    id: str = Field(..., description="Unique role ID")
    type: str = Field(..., description="Role type (e.g., SUPER_ADMIN, ORG_ADMIN)")
    status: str = Field(..., description="Role status")
    created: datetime = Field(..., description="Role creation timestamp")
    last_updated: datetime | None = Field(
        default=None, alias="lastUpdated", description="Last update timestamp"
    )

    # Assignment information
    assigned_users: list[str] = Field(
        default_factory=list, description="List of user IDs assigned this role"
    )
    assigned_groups: list[str] = Field(
        default_factory=list, description="List of group IDs assigned this role"
    )

    # Role scope and permissions
    resource_sets: list[dict[str, Any]] = Field(
        default_factory=list, description="Resource sets this role applies to"
    )
    permissions: list[str] = Field(
        default_factory=list, description="Specific permissions granted"
    )

    def is_super_admin(self) -> bool:
        """Check if this is a super admin role."""
        return self.type.upper() in ["SUPER_ADMIN", "SUPER_ADMINISTRATOR"]

    def is_admin_role(self) -> bool:
        """Check if this is any type of admin role."""
        admin_patterns = ["ADMIN", "ADMINISTRATOR", "SUPER"]
        return any(pattern in self.type.upper() for pattern in admin_patterns)

    def total_assignments(self) -> int:
        """Get total number of assignments for this role."""
        return len(self.assigned_users) + len(self.assigned_groups)
