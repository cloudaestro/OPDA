"""
Main Okta API client with authentication and entity fetching.

Integrates rate limiting, pagination, and structured data models
to provide a high-level interface for Okta API operations.
"""

from datetime import datetime
from typing import Any

import structlog
from okta.client import Client as OktaSDKClient
from okta.models import Application, Group, User

from opda.client.pagination import OktaPaginator
from opda.client.rate_limiter import OktaRateLimiter
from opda.config.settings import OktaSettings
from opda.models.okta_entities import (
    OktaApplication,
    OktaGroup,
    OktaUser,
    SystemLogEvent,
)

logger = structlog.get_logger(__name__)


class OktaClientError(Exception):
    """Base exception for Okta client operations."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthenticationError(OktaClientError):
    """Raised when Okta authentication fails."""


class OktaClient:
    """
    High-level Okta API client with rate limiting and pagination.

    Provides methods to fetch users, groups, applications, roles, and
    system logs with automatic retry, pagination, and data validation.
    """

    def __init__(
        self,
        settings: OktaSettings,
        rate_limiter: OktaRateLimiter | None = None,
        paginator: OktaPaginator | None = None,
    ) -> None:
        self.settings = settings
        self.rate_limiter = rate_limiter or OktaRateLimiter()
        self.paginator = paginator or OktaPaginator()

        # Configure Okta SDK client
        okta_config_dict = {
            "orgUrl": f"https://{self.settings.domain}",
            "token": self.settings.token,
            "connectionTimeout": 30,
            "requestTimeout": 0,  # No request timeout (handled by rate limiter)
        }

        self._sdk_client = OktaSDKClient(okta_config_dict)
        self._session_start = datetime.utcnow()

        logger.info(
            "Okta client initialized",
            domain=self.settings.domain,
            rate_limit_per_minute=self.rate_limiter.max_requests_per_minute,
            page_size=self.paginator.page_size,
        )

    async def authenticate(self) -> bool:
        """
        Verify authentication with Okta API.

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            # Test authentication by fetching current user
            current_user = await self.rate_limiter.execute_with_retry(
                self._sdk_client.get_user, "me"
            )

            if current_user:
                logger.info(
                    "Authentication successful",
                    user_id=current_user.id,
                    domain=self.settings.domain,
                )
                return True

        except Exception as e:
            logger.error(
                "Authentication failed",
                error=str(e),
                domain=self.settings.domain,
            )
            raise AuthenticationError(f"Failed to authenticate with Okta: {e}") from e

        return False

    async def get_all_users(
        self,
        active_only: bool = True,
        include_groups: bool = True,
    ) -> list[OktaUser]:
        """
        Fetch all users from Okta.

        Args:
            active_only: Only return active users
            include_groups: Include group memberships

        Returns:
            List of validated OktaUser models
        """
        logger.info(
            "Fetching all users",
            active_only=active_only,
            include_groups=include_groups,
        )

        query_params = {}
        if active_only:
            query_params["filter"] = 'status eq "ACTIVE"'

        # Fetch users using pagination
        raw_users = await self.paginator.paginate_all(
            self._fetch_users_page, **query_params
        )

        # Convert to our data models
        validated_users: list[OktaUser] = []
        for raw_user in raw_users:
            try:
                # Convert SDK user to our model
                user_data = self._convert_sdk_user_to_dict(raw_user)

                # Add group memberships if requested
                if include_groups:
                    user_data["group_memberships"] = await self._get_user_groups(
                        raw_user.id
                    )

                validated_user = OktaUser(**user_data)
                validated_users.append(validated_user)

            except Exception as e:
                logger.warning(
                    "Failed to validate user data",
                    user_id=getattr(raw_user, "id", "unknown"),
                    error=str(e),
                )
                continue

        logger.info(
            "User fetch completed",
            total_users=len(validated_users),
            duration_seconds=(datetime.utcnow() - self._session_start).total_seconds(),
        )

        return validated_users

    async def get_all_groups(self, include_members: bool = True) -> list[OktaGroup]:
        """
        Fetch all groups from Okta.

        Args:
            include_members: Include group member lists

        Returns:
            List of validated OktaGroup models
        """
        logger.info("Fetching all groups", include_members=include_members)

        # Fetch groups using pagination
        raw_groups = await self.paginator.paginate_all(self._fetch_groups_page)

        # Convert to our data models
        validated_groups: list[OktaGroup] = []
        for raw_group in raw_groups:
            try:
                # Convert SDK group to our model
                group_data = self._convert_sdk_group_to_dict(raw_group)

                # Add member lists if requested
                if include_members:
                    group_data["members"] = await self._get_group_members(raw_group.id)

                validated_group = OktaGroup(**group_data)
                validated_groups.append(validated_group)

            except Exception as e:
                logger.warning(
                    "Failed to validate group data",
                    group_id=getattr(raw_group, "id", "unknown"),
                    error=str(e),
                )
                continue

        logger.info("Group fetch completed", total_groups=len(validated_groups))
        return validated_groups

    async def get_all_applications(self) -> list[OktaApplication]:
        """
        Fetch all applications from Okta.

        Returns:
            List of validated OktaApplication models
        """
        logger.info("Fetching all applications")

        # Fetch applications using pagination
        raw_apps = await self.paginator.paginate_all(self._fetch_applications_page)

        # Convert to our data models
        validated_apps: list[OktaApplication] = []
        for raw_app in raw_apps:
            try:
                app_data = self._convert_sdk_application_to_dict(raw_app)
                validated_app = OktaApplication(**app_data)
                validated_apps.append(validated_app)

            except Exception as e:
                logger.warning(
                    "Failed to validate application data",
                    app_id=getattr(raw_app, "id", "unknown"),
                    error=str(e),
                )
                continue

        logger.info("Application fetch completed", total_apps=len(validated_apps))
        return validated_apps

    async def get_system_logs(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[SystemLogEvent]:
        """
        Fetch system log events from Okta.

        Args:
            since: Start date for log retrieval
            until: End date for log retrieval
            limit: Maximum number of events to retrieve

        Returns:
            List of validated SystemLogEvent models
        """
        logger.info(
            "Fetching system logs",
            since=since.isoformat() if since else None,
            until=until.isoformat() if until else None,
            limit=limit,
        )

        query_params = {}
        if since:
            query_params["since"] = since.isoformat()
        if until:
            query_params["until"] = until.isoformat()

        # Configure paginator with limit if specified
        if limit:
            self.paginator.max_items = limit

        # Fetch logs using pagination
        raw_logs = await self.paginator.paginate_all(
            self._fetch_system_logs_page, **query_params
        )

        # Convert to our data models
        validated_logs: list[SystemLogEvent] = []
        for raw_log in raw_logs:
            try:
                log_data = self._convert_sdk_log_to_dict(raw_log)
                validated_log = SystemLogEvent(**log_data)
                validated_logs.append(validated_log)

            except Exception as e:
                logger.warning(
                    "Failed to validate log event data",
                    log_uuid=getattr(raw_log, "uuid", "unknown"),
                    error=str(e),
                )
                continue

        logger.info("System logs fetch completed", total_events=len(validated_logs))
        return validated_logs

    async def close(self) -> None:
        """Clean up client resources."""
        logger.info(
            "Closing Okta client",
            total_requests=self.rate_limiter.get_statistics()["total_requests"],
            session_duration=(datetime.utcnow() - self._session_start).total_seconds(),
        )

    # Internal pagination methods

    async def _fetch_users_page(self, **kwargs: Any) -> list[User]:
        """Fetch a single page of users."""
        return await self.rate_limiter.execute_with_retry(
            self._sdk_client.list_users, **kwargs
        )

    async def _fetch_groups_page(self, **kwargs: Any) -> list[Group]:
        """Fetch a single page of groups."""
        return await self.rate_limiter.execute_with_retry(
            self._sdk_client.list_groups, **kwargs
        )

    async def _fetch_applications_page(self, **kwargs: Any) -> list[Application]:
        """Fetch a single page of applications."""
        return await self.rate_limiter.execute_with_retry(
            self._sdk_client.list_applications, **kwargs
        )

    async def _fetch_system_logs_page(self, **kwargs: Any) -> list[Any]:
        """Fetch a single page of system logs."""
        return await self.rate_limiter.execute_with_retry(
            self._sdk_client.get_logs, **kwargs
        )

    # Internal helper methods for group memberships

    async def _get_user_groups(self, user_id: str) -> list[str]:
        """Get group IDs for a specific user."""
        try:
            groups = await self.rate_limiter.execute_with_retry(
                self._sdk_client.list_user_groups, user_id
            )
            return [group.id for group in groups if hasattr(group, "id")]
        except Exception as e:
            logger.warning(
                "Failed to fetch user groups",
                user_id=user_id,
                error=str(e),
            )
            return []

    async def _get_group_members(self, group_id: str) -> list[str]:
        """Get user IDs for group members."""
        try:
            members = await self.rate_limiter.execute_with_retry(
                self._sdk_client.list_group_users, group_id
            )
            return [member.id for member in members if hasattr(member, "id")]
        except Exception as e:
            logger.warning(
                "Failed to fetch group members",
                group_id=group_id,
                error=str(e),
            )
            return []

    # Internal data conversion methods

    def _convert_sdk_user_to_dict(self, sdk_user: User) -> dict[str, Any]:
        """Convert Okta SDK User to dictionary for our model."""
        return {
            "id": sdk_user.id or "",
            "login": getattr(sdk_user.profile, "login", "") or "",
            "email": getattr(sdk_user.profile, "email", "") or "",
            "first_name": getattr(sdk_user.profile, "firstName", "") or "",
            "last_name": getattr(sdk_user.profile, "lastName", "") or "",
            "display_name": getattr(sdk_user.profile, "displayName", "") or "",
            "status": sdk_user.status or "UNKNOWN",
            "created": sdk_user.created,
            "activated": sdk_user.activated,
            "last_login": sdk_user.last_login,
            "last_updated": sdk_user.last_updated,
            "password_changed": sdk_user.password_changed,
            "type": getattr(sdk_user.type, "id", "") if sdk_user.type else "",
            "group_memberships": [],  # Will be populated separately if requested
        }

    def _convert_sdk_group_to_dict(self, sdk_group: Group) -> dict[str, Any]:
        """Convert Okta SDK Group to dictionary for our model."""
        return {
            "id": sdk_group.id or "",
            "name": getattr(sdk_group.profile, "name", "") or "",
            "description": getattr(sdk_group.profile, "description", "") or "",
            "type": sdk_group.type or "OKTA_GROUP",
            "created": sdk_group.created,
            "last_updated": sdk_group.last_updated,
            "last_membership_updated": sdk_group.last_membership_updated,
            "members": [],  # Will be populated separately if requested
        }

    def _convert_sdk_application_to_dict(self, sdk_app: Application) -> dict[str, Any]:
        """Convert Okta SDK Application to dictionary for our model."""
        return {
            "id": sdk_app.id or "",
            "name": getattr(sdk_app, "name", "") or "",
            "label": getattr(sdk_app, "label", "") or "",
            "status": sdk_app.status or "UNKNOWN",
            "sign_on_mode": getattr(sdk_app, "signOnMode", "") or "",
            "created": sdk_app.created,
            "last_updated": sdk_app.last_updated,
            "features": getattr(sdk_app, "features", []) or [],
            "visibility": (
                getattr(sdk_app.visibility, "hide", {})
                if sdk_app.visibility
                else {}
            ),
        }

    def _convert_sdk_log_to_dict(self, sdk_log: Any) -> dict[str, Any]:
        """Convert Okta SDK LogEvent to dictionary for our model."""
        return {
            "uuid": getattr(sdk_log, "uuid", "") or "",
            "published": getattr(sdk_log, "published", None),
            "event_type": getattr(sdk_log, "eventType", "") or "",
            "version": getattr(sdk_log, "version", "") or "",
            "severity": getattr(sdk_log, "severity", "INFO") or "INFO",
            "legacy_event_type": getattr(sdk_log, "legacyEventType", "") or "",
            "display_message": getattr(sdk_log, "displayMessage", "") or "",
            "actor": self._extract_actor_info(sdk_log),
            "client": self._extract_client_info(sdk_log),
            "target": self._extract_target_info(sdk_log),
            "transaction": self._extract_transaction_info(sdk_log),
            "debug_context": self._extract_debug_context(sdk_log),
            "authentication_context": self._extract_auth_context(sdk_log),
            "security_context": self._extract_security_context(sdk_log),
            "outcome": self._extract_outcome_info(sdk_log),
        }

    def _extract_actor_info(self, sdk_log: Any) -> dict[str, Any]:
        """Extract actor information from log event."""
        actor = getattr(sdk_log, "actor", None)
        if not actor:
            return {}

        return {
            "id": getattr(actor, "id", "") or "",
            "type": getattr(actor, "type", "") or "",
            "alternate_id": getattr(actor, "alternateId", "") or "",
            "display_name": getattr(actor, "displayName", "") or "",
        }

    def _extract_client_info(self, sdk_log: Any) -> dict[str, Any]:
        """Extract client information from log event."""
        client = getattr(sdk_log, "client", None)
        if not client:
            return {}

        return {
            "user_agent": getattr(client, "userAgent", {}) or {},
            "zone": getattr(client, "zone", "") or "",
            "device": getattr(client, "device", "") or "",
            "id": getattr(client, "id", "") or "",
            "ip_address": getattr(client, "ipAddress", "") or "",
        }

    def _extract_target_info(self, sdk_log: Any) -> list[dict[str, Any]]:
        """Extract target information from log event."""
        targets = getattr(sdk_log, "target", [])
        if not targets:
            return []

        target_list = []
        for target in targets:
            target_info = {
                "id": getattr(target, "id", "") or "",
                "type": getattr(target, "type", "") or "",
                "alternate_id": getattr(target, "alternateId", "") or "",
                "display_name": getattr(target, "displayName", "") or "",
            }
            target_list.append(target_info)

        return target_list

    def _extract_transaction_info(self, sdk_log: Any) -> dict[str, Any]:
        """Extract transaction information from log event."""
        transaction = getattr(sdk_log, "transaction", None)
        if not transaction:
            return {}

        return {
            "type": getattr(transaction, "type", "") or "",
            "id": getattr(transaction, "id", "") or "",
        }

    def _extract_debug_context(self, sdk_log: Any) -> dict[str, Any]:
        """Extract debug context from log event."""
        debug_context = getattr(sdk_log, "debugContext", None)
        if not debug_context:
            return {}

        return {
            "debug_data": getattr(debug_context, "debugData", {}) or {},
        }

    def _extract_auth_context(self, sdk_log: Any) -> dict[str, Any]:
        """Extract authentication context from log event."""
        auth_context = getattr(sdk_log, "authenticationContext", None)
        if not auth_context:
            return {}

        return {
            "authentication_provider": (
                getattr(auth_context, "authenticationProvider", "") or ""
            ),
            "credential_provider": (
                getattr(auth_context, "credentialProvider", "") or ""
            ),
            "credential_type": getattr(auth_context, "credentialType", "") or "",
            "issuer": getattr(auth_context, "issuer", {}) or {},
            "external_session_id": getattr(auth_context, "externalSessionId", "") or "",
        }

    def _extract_security_context(self, sdk_log: Any) -> dict[str, Any]:
        """Extract security context from log event."""
        security_context = getattr(sdk_log, "securityContext", None)
        if not security_context:
            return {}

        return {
            "as_number": getattr(security_context, "asNumber", None),
            "as_org": getattr(security_context, "asOrg", "") or "",
            "isp": getattr(security_context, "isp", "") or "",
            "domain": getattr(security_context, "domain", "") or "",
            "is_proxy": getattr(security_context, "isProxy", None),
        }

    def _extract_outcome_info(self, sdk_log: Any) -> dict[str, Any]:
        """Extract outcome information from log event."""
        outcome = getattr(sdk_log, "outcome", None)
        if not outcome:
            return {}

        return {
            "result": getattr(outcome, "result", "") or "",
            "reason": getattr(outcome, "reason", "") or "",
        }

    async def get_client_statistics(self) -> dict[str, Any]:
        """Get comprehensive client usage statistics."""
        rate_limit_stats = self.rate_limiter.get_statistics()
        pagination_stats = self.paginator.get_statistics()

        return {
            "session_duration_seconds": (
                datetime.utcnow() - self._session_start
            ).total_seconds(),
            "rate_limiter": rate_limit_stats,
            "paginator": pagination_stats,
        }

