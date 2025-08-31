"""Tests for Okta client functionality."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest

from opda.client.okta_client import AuthenticationError, OktaClient, OktaClientError
from opda.client.pagination import OktaPaginator
from opda.client.rate_limiter import OktaRateLimiter
from opda.config.settings import OktaSettings
from opda.models.okta_entities import (
    OktaApplication,
    OktaGroup,
    OktaUser,
    SystemLogEvent,
)


class TestOktaClient:
    """Test OktaClient functionality."""

    @pytest.fixture
    def settings(self) -> OktaSettings:
        """Create test settings."""
        return OktaSettings(
            domain="test.okta.com",
            token="test_token_12345",
        )

    @pytest.fixture
    def mock_rate_limiter(self) -> Mock:
        """Create mock rate limiter."""
        limiter = Mock(spec=OktaRateLimiter)
        limiter.execute_with_retry = AsyncMock()
        limiter.get_statistics.return_value = {
            "total_requests": 10,
            "total_retries": 2,
            "total_rate_limit_hits": 1,
        }
        return limiter

    @pytest.fixture
    def mock_paginator(self) -> Mock:
        """Create mock paginator."""
        paginator = Mock(spec=OktaPaginator)
        paginator.paginate_all = AsyncMock()
        paginator.get_statistics.return_value = {
            "pages_fetched": 3,
            "items_fetched": 15,
            "total_api_calls": 3,
        }
        return paginator

    @pytest.fixture
    def client(
        self,
        settings: OktaSettings,
        mock_rate_limiter: Mock,
        mock_paginator: Mock,
    ) -> OktaClient:
        """Create test client with mocked dependencies."""
        return OktaClient(
            settings=settings,
            rate_limiter=mock_rate_limiter,
            paginator=mock_paginator,
        )

    @pytest.mark.asyncio
    async def test_successful_authentication(self, client: OktaClient) -> None:
        """Test successful authentication."""
        # Mock successful authentication response
        mock_user = Mock()
        mock_user.id = "test_user_id"
        client.rate_limiter.execute_with_retry.return_value = mock_user

        result = await client.authenticate()

        assert result is True
        client.rate_limiter.execute_with_retry.assert_called_once()

    @pytest.mark.asyncio
    async def test_failed_authentication(self, client: OktaClient) -> None:
        """Test failed authentication."""
        client.rate_limiter.execute_with_retry.side_effect = RuntimeError(
            "Invalid token"
        )

        with pytest.raises(
            AuthenticationError, match="Failed to authenticate with Okta"
        ):
            await client.authenticate()

    @pytest.mark.asyncio
    async def test_get_all_users_basic(self, client: OktaClient) -> None:
        """Test basic user fetching."""
        # Mock SDK user objects
        mock_users = [
            self._create_mock_user("user1", "john@example.com", "ACTIVE"),
            self._create_mock_user("user2", "jane@example.com", "ACTIVE"),
        ]

        client.paginator.paginate_all.return_value = mock_users
        client._get_user_groups = AsyncMock(return_value=["group1", "group2"])

        users = await client.get_all_users(include_groups=True)

        assert len(users) == 2
        assert isinstance(users[0], OktaUser)
        assert users[0].id == "user1"
        assert users[0].email == "john@example.com"
        assert users[0].group_memberships == ["group1", "group2"]

    @pytest.mark.asyncio
    async def test_get_all_users_active_only(self, client: OktaClient) -> None:
        """Test filtering active users only."""
        mock_users = [self._create_mock_user("user1", "test@example.com", "ACTIVE")]
        client.paginator.paginate_all.return_value = mock_users

        await client.get_all_users(active_only=True, include_groups=False)

        # Check that filter was applied
        call_args = client.paginator.paginate_all.call_args
        assert 'filter' in call_args[1]
        assert 'status eq "ACTIVE"' in call_args[1]['filter']

    @pytest.mark.asyncio
    async def test_get_all_groups_basic(self, client: OktaClient) -> None:
        """Test basic group fetching."""
        mock_groups = [
            self._create_mock_group("group1", "Admins"),
            self._create_mock_group("group2", "Users"),
        ]

        client.paginator.paginate_all.return_value = mock_groups
        client._get_group_members = AsyncMock(return_value=["user1", "user2"])

        groups = await client.get_all_groups(include_members=True)

        assert len(groups) == 2
        assert isinstance(groups[0], OktaGroup)
        assert groups[0].id == "group1"
        assert groups[0].name == "Admins"
        assert groups[0].members == ["user1", "user2"]

    @pytest.mark.asyncio
    async def test_get_all_applications(self, client: OktaClient) -> None:
        """Test application fetching."""
        mock_apps = [
            self._create_mock_application("app1", "Test App 1"),
            self._create_mock_application("app2", "Test App 2"),
        ]

        client.paginator.paginate_all.return_value = mock_apps

        apps = await client.get_all_applications()

        assert len(apps) == 2
        assert isinstance(apps[0], OktaApplication)
        assert apps[0].id == "app1"
        assert apps[0].name == "Test App 1"

    @pytest.mark.asyncio
    async def test_get_system_logs(self, client: OktaClient) -> None:
        """Test system log fetching."""
        now = datetime.utcnow()
        since = now - timedelta(hours=1)

        mock_logs = [
            self._create_mock_log_event("log1", "user.authentication.success"),
            self._create_mock_log_event("log2", "user.session.start"),
        ]

        client.paginator.paginate_all.return_value = mock_logs

        logs = await client.get_system_logs(since=since, limit=100)

        assert len(logs) == 2
        assert isinstance(logs[0], SystemLogEvent)
        assert logs[0].uuid == "log1"
        assert logs[0].event_type == "user.authentication.success"

        # Check that pagination limit was set
        assert client.paginator.max_items == 100

    @pytest.mark.asyncio
    async def test_data_validation_error_handling(self, client: OktaClient) -> None:
        """Test handling of invalid data during conversion."""
        # Mock user with invalid data
        invalid_user = Mock()
        invalid_user.id = None  # Invalid - should cause validation error
        invalid_user.profile = Mock()
        invalid_user.profile.login = None

        client.paginator.paginate_all.return_value = [invalid_user]

        users = await client.get_all_users()

        # Should return empty list when validation fails
        assert len(users) == 0

    @pytest.mark.asyncio
    async def test_group_membership_error_handling(self, client: OktaClient) -> None:
        """Test error handling when fetching group memberships."""
        mock_user = self._create_mock_user("user1", "test@example.com", "ACTIVE")
        client.paginator.paginate_all.return_value = [mock_user]

        # Mock group fetching to fail
        client._get_user_groups = AsyncMock(side_effect=RuntimeError("API error"))

        users = await client.get_all_users(include_groups=True)

        # Should still return user but with empty groups
        assert len(users) == 1
        assert users[0].group_memberships == []

    @pytest.mark.asyncio
    async def test_client_statistics(self, client: OktaClient) -> None:
        """Test client statistics aggregation."""
        stats = await client.get_client_statistics()

        assert "session_duration_seconds" in stats
        assert "rate_limiter" in stats
        assert "paginator" in stats
        assert stats["rate_limiter"]["total_requests"] == 10
        assert stats["paginator"]["pages_fetched"] == 3

    @pytest.mark.asyncio
    async def test_client_cleanup(self, client: OktaClient) -> None:
        """Test client resource cleanup."""
        await client.close()

        # Should complete without errors
        assert True

    def _create_mock_user(self, user_id: str, email: str, status: str) -> Mock:
        """Create mock SDK user object."""
        user = Mock()
        user.id = user_id
        user.status = status
        user.created = datetime.utcnow()
        user.activated = datetime.utcnow()
        user.last_login = datetime.utcnow()
        user.last_updated = datetime.utcnow()
        user.password_changed = datetime.utcnow()
        user.type = Mock()
        user.type.id = "OKTA_USER"

        user.profile = Mock()
        user.profile.login = email
        user.profile.email = email
        user.profile.firstName = "Test"
        user.profile.lastName = "User"
        user.profile.displayName = f"Test User {user_id}"

        return user

    def _create_mock_group(self, group_id: str, name: str) -> Mock:
        """Create mock SDK group object."""
        group = Mock()
        group.id = group_id
        group.type = "OKTA_GROUP"
        group.created = datetime.utcnow()
        group.last_updated = datetime.utcnow()
        group.last_membership_updated = datetime.utcnow()

        group.profile = Mock()
        group.profile.name = name
        group.profile.description = f"Test group: {name}"

        return group

    def _create_mock_application(self, app_id: str, name: str) -> Mock:
        """Create mock SDK application object."""
        app = Mock()
        app.id = app_id
        app.name = name
        app.label = name
        app.status = "ACTIVE"
        app.signOnMode = "SAML_2_0"
        app.created = datetime.utcnow()
        app.last_updated = datetime.utcnow()
        app.features = ["SSO"]
        app.visibility = Mock()
        app.visibility.hide = {"iOS": False, "web": False}

        return app

    def _create_mock_log_event(self, uuid: str, event_type: str) -> Mock:
        """Create mock SDK log event object."""
        log = Mock()
        log.uuid = uuid
        log.published = datetime.utcnow()
        log.eventType = event_type
        log.version = "0"
        log.severity = "INFO"
        log.legacyEventType = event_type
        log.displayMessage = f"Test event: {event_type}"

        # Mock nested objects
        log.actor = Mock()
        log.actor.id = "actor_id"
        log.actor.type = "User"
        log.actor.alternateId = "test@example.com"
        log.actor.displayName = "Test User"

        log.client = Mock()
        log.client.userAgent = {"rawUserAgent": "Mozilla/5.0..."}
        log.client.zone = "null"
        log.client.device = "Unknown"
        log.client.id = "client_id"
        log.client.ipAddress = "192.168.1.1"

        log.target = []
        log.transaction = Mock()
        log.transaction.type = "WEB"
        log.transaction.id = "transaction_id"

        log.debugContext = Mock()
        log.debugContext.debugData = {}

        log.authenticationContext = Mock()
        log.authenticationContext.authenticationProvider = (
            "OKTA_AUTHENTICATION_PROVIDER"
        )
        log.authenticationContext.credentialProvider = "OKTA_CREDENTIAL_PROVIDER"
        log.authenticationContext.credentialType = "PASSWORD"

        log.securityContext = Mock()
        log.securityContext.asNumber = 12345
        log.securityContext.asOrg = "Test ISP"
        log.securityContext.isp = "Test ISP"
        log.securityContext.domain = "example.com"
        log.securityContext.isProxy = False

        log.outcome = Mock()
        log.outcome.result = "SUCCESS"
        log.outcome.reason = ""

        return log


class TestOktaClientError:
    """Test custom exception classes."""

    def test_okta_client_error(self) -> None:
        """Test base OktaClientError."""
        error = OktaClientError("Test error", status_code=400)
        assert str(error) == "Test error"
        assert error.status_code == 400

    def test_authentication_error(self) -> None:
        """Test AuthenticationError inheritance."""
        error = AuthenticationError("Auth failed")
        assert isinstance(error, OktaClientError)
        assert str(error) == "Auth failed"

