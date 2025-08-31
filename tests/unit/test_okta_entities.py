"""Tests for Okta entity data models."""

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from opda.models.okta_entities import (
    AppStatus,
    GroupType,
    OktaApplication,
    OktaGroup,
    OktaProfile,
    OktaRole,
    OktaUser,
    UserStatus,
)


class TestOktaProfile:
    """Test OktaProfile model."""

    def test_valid_profile(self) -> None:
        """Test valid profile creation."""
        profile = OktaProfile(
            login="john.doe@company.com",
            email="john.doe@company.com",
            firstName="John",
            lastName="Doe",
            displayName="John Doe",
            employeeNumber="12345",
            department="Engineering",
        )

        assert profile.login == "john.doe@company.com"
        assert profile.email == "john.doe@company.com"
        assert profile.first_name == "John"
        assert profile.last_name == "Doe"
        assert profile.display_name == "John Doe"
        assert profile.employee_number == "12345"
        assert profile.department == "Engineering"

    def test_invalid_email(self) -> None:
        """Test invalid email validation."""
        with pytest.raises(ValidationError, match="Invalid email format"):
            OktaProfile(email="invalid-email")

    def test_empty_profile(self) -> None:
        """Test empty profile is valid."""
        profile = OktaProfile()
        assert profile.login is None
        assert profile.email is None


class TestOktaUser:
    """Test OktaUser model."""

    def test_valid_user(self) -> None:
        """Test valid user creation."""
        now = datetime.utcnow()
        user = OktaUser(
            id="00u123456789abcdef",
            status=UserStatus.ACTIVE,
            created=now,
            activated=now,
            lastLogin=now - timedelta(days=1),
            profile=OktaProfile(
                login="john.doe@company.com",
                email="john.doe@company.com",
            ),
        )

        assert user.id == "00u123456789abcdef"
        assert user.status == UserStatus.ACTIVE
        assert user.is_active() is True
        assert user.profile.login == "john.doe@company.com"

    def test_invalid_user_id(self) -> None:
        """Test invalid user ID validation."""
        with pytest.raises(ValidationError, match="Invalid Okta user ID"):
            OktaUser(
                id="short",
                status=UserStatus.ACTIVE,
                created=datetime.utcnow(),
                profile=OktaProfile(),
            )

    def test_days_since_last_login(self) -> None:
        """Test last login calculation."""
        # User with recent login
        recent_login = datetime.utcnow() - timedelta(days=5)
        user = OktaUser(
            id="00u123456789abcdef",
            status=UserStatus.ACTIVE,
            created=datetime.utcnow(),
            lastLogin=recent_login,
            profile=OktaProfile(),
        )

        days_since = user.days_since_last_login()
        assert days_since is not None
        assert 4 <= days_since <= 6  # Account for test execution time

    def test_stale_account_detection(self) -> None:
        """Test stale account detection."""
        # Stale user (last login > 90 days)
        old_login = datetime.utcnow() - timedelta(days=100)
        stale_user = OktaUser(
            id="00u123456789abcdef",
            status=UserStatus.ACTIVE,
            created=datetime.utcnow(),
            lastLogin=old_login,
            profile=OktaProfile(),
        )

        assert stale_user.is_stale_account() is True
        assert stale_user.is_stale_account(days_threshold=30) is True
        assert stale_user.is_stale_account(days_threshold=200) is False

    def test_no_last_login(self) -> None:
        """Test user with no last login."""
        user = OktaUser(
            id="00u123456789abcdef",
            status=UserStatus.ACTIVE,
            created=datetime.utcnow(),
            profile=OktaProfile(),
        )

        assert user.days_since_last_login() is None
        assert user.is_stale_account() is False


class TestOktaGroup:
    """Test OktaGroup model."""

    def test_valid_group(self) -> None:
        """Test valid group creation."""
        group = OktaGroup(
            id="00g123456789abcdef",
            name="Engineering Team",
            description="All engineering staff",
            type=GroupType.OKTA_GROUP,
            created=datetime.utcnow(),
            members=["user1", "user2", "user3"],
        )

        assert group.id == "00g123456789abcdef"
        assert group.name == "Engineering Team"
        assert group.type == GroupType.OKTA_GROUP
        assert group.member_count() == 3

    def test_empty_group_name(self) -> None:
        """Test empty group name validation."""
        with pytest.raises(ValidationError, match="Group name cannot be empty"):
            OktaGroup(
                id="00g123456789abcdef",
                name="   ",  # Whitespace only
                type=GroupType.OKTA_GROUP,
                created=datetime.utcnow(),
            )

    def test_privileged_group_detection(self) -> None:
        """Test privileged group detection."""
        # Privileged groups
        admin_group = OktaGroup(
            id="00g123456789abcdef",
            name="Domain Administrators",
            type=GroupType.AD_GROUP,
            created=datetime.utcnow(),
        )

        super_group = OktaGroup(
            id="00g123456789abcdef",
            name="Super Users",
            type=GroupType.OKTA_GROUP,
            created=datetime.utcnow(),
        )

        # Regular group
        regular_group = OktaGroup(
            id="00g123456789abcdef",
            name="Marketing Team",
            type=GroupType.OKTA_GROUP,
            created=datetime.utcnow(),
        )

        assert admin_group.is_privileged_group() is True
        assert super_group.is_privileged_group() is True
        assert regular_group.is_privileged_group() is False


class TestOktaApplication:
    """Test OktaApplication model."""

    def test_valid_application(self) -> None:
        """Test valid application creation."""
        app = OktaApplication(
            id="0oa123456789abcdef",
            name="salesforce",
            label="Salesforce",
            status=AppStatus.ACTIVE,
            created=datetime.utcnow(),
            signOnMode="SAML_2_0",
            assigned_users=["user1", "user2"],
            assigned_groups=["group1"],
        )

        assert app.id == "0oa123456789abcdef"
        assert app.name == "salesforce"
        assert app.label == "Salesforce"
        assert app.is_active() is True
        assert app.total_assignments() == 3

    def test_empty_name_validation(self) -> None:
        """Test empty name validation."""
        with pytest.raises(
            ValidationError, match="Name and label fields cannot be empty"
        ):
            OktaApplication(
                id="0oa123456789abcdef",
                name="",  # Empty name
                label="Valid Label",
                status=AppStatus.ACTIVE,
                created=datetime.utcnow(),
            )

    def test_high_privilege_app_detection(self) -> None:
        """Test high privilege application detection."""
        # High privilege apps
        aws_app = OktaApplication(
            id="0oa123456789abcdef",
            name="aws_console",
            label="AWS Management Console",
            status=AppStatus.ACTIVE,
            created=datetime.utcnow(),
        )

        admin_app = OktaApplication(
            id="0oa123456789abcdef",
            name="okta_admin",
            label="Okta Admin Console",
            status=AppStatus.ACTIVE,
            created=datetime.utcnow(),
        )

        # Regular app
        slack_app = OktaApplication(
            id="0oa123456789abcdef",
            name="slack",
            label="Slack Workspace",
            status=AppStatus.ACTIVE,
            created=datetime.utcnow(),
        )

        assert aws_app.is_high_privilege_app() is True
        assert admin_app.is_high_privilege_app() is True
        assert slack_app.is_high_privilege_app() is False


class TestOktaRole:
    """Test OktaRole model."""

    def test_valid_role(self) -> None:
        """Test valid role creation."""
        role = OktaRole(
            id="irl123456789abcdef",
            type="ORG_ADMIN",
            status="ACTIVE",
            created=datetime.utcnow(),
            assigned_users=["user1", "user2"],
            assigned_groups=["group1"],
            permissions=["users.read", "groups.manage"],
        )

        assert role.id == "irl123456789abcdef"
        assert role.type == "ORG_ADMIN"
        assert role.total_assignments() == 3
        assert len(role.permissions) == 2

    def test_super_admin_detection(self) -> None:
        """Test super admin role detection."""
        super_admin = OktaRole(
            id="irl123456789abcdef",
            type="SUPER_ADMIN",
            status="ACTIVE",
            created=datetime.utcnow(),
        )

        org_admin = OktaRole(
            id="irl123456789abcdef",
            type="ORG_ADMIN",
            status="ACTIVE",
            created=datetime.utcnow(),
        )

        regular_role = OktaRole(
            id="irl123456789abcdef",
            type="READ_ONLY_ADMIN",
            status="ACTIVE",
            created=datetime.utcnow(),
        )

        assert super_admin.is_super_admin() is True
        assert super_admin.is_admin_role() is True

        assert org_admin.is_super_admin() is False
        assert org_admin.is_admin_role() is True

        assert regular_role.is_super_admin() is False
        assert regular_role.is_admin_role() is True  # Contains "ADMIN"

    def test_admin_role_detection(self) -> None:
        """Test admin role detection."""
        roles_data = [
            ("SUPER_ADMIN", True, True),
            ("ORG_ADMIN", False, True),
            ("APP_ADMIN", False, True),
            ("GROUP_ADMINISTRATOR", False, True),
            ("HELP_DESK_ADMIN", False, True),
            ("READ_ONLY", False, False),
            ("USER", False, False),
        ]

        for role_type, expected_super, expected_admin in roles_data:
            role = OktaRole(
                id="irl123456789abcdef",
                type=role_type,
                status="ACTIVE",
                created=datetime.utcnow(),
            )

            assert role.is_super_admin() == expected_super
            assert role.is_admin_role() == expected_admin
