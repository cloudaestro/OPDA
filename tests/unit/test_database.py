"""Tests for database storage functionality."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from opda.models.audit_results import (
    AuditFinding,
    AuditSession,
    AuditStatus,
    FindingType,
    RiskLevel,
)
from opda.models.okta_entities import (
    ApplicationStatus,
    GroupType,
    OktaApplication,
    OktaGroup,
    OktaUser,
    UserStatus,
)
from opda.storage.database import DatabaseError, DatabaseManager


class TestDatabaseManager:
    """Test DatabaseManager functionality."""

    @pytest.fixture
    async def db_manager(self) -> DatabaseManager:
        """Create temporary database manager for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_opda.db"
            manager = DatabaseManager(db_path)
            await manager.initialize_schema()
            yield manager

    @pytest.fixture
    def sample_audit_session(self) -> AuditSession:
        """Create sample audit session for testing."""
        findings = [
            AuditFinding(
                id="finding_001",
                finding_type=FindingType.PRIVILEGE_ESCALATION,
                risk_level=RiskLevel.HIGH,
                title="Excessive admin privileges",
                description="User has admin access to multiple systems",
                affected_users=["user1", "user2"],
                affected_applications=["app1"],
                violated_policies=["admin_policy"],
                remediation_required=True,
                recommended_actions=["Remove excess privileges"],
            ),
            AuditFinding(
                id="finding_002",
                finding_type=FindingType.STALE_ACCESS,
                risk_level=RiskLevel.MEDIUM,
                title="Inactive user access",
                description="User inactive but still has access",
                affected_users=["inactive_user"],
            ),
        ]

        return AuditSession(
            session_id="session_001",
            status=AuditStatus.COMPLETED,
            started_at=datetime.utcnow() - timedelta(hours=1),
            completed_at=datetime.utcnow(),
            audit_scope={"users": True, "groups": True},
            policies_evaluated=["policy1", "policy2"],
            total_users_analyzed=100,
            total_groups_analyzed=25,
            total_applications_analyzed=15,
            findings=findings,
        )

    @pytest.fixture
    def sample_users(self) -> list[OktaUser]:
        """Create sample users for testing."""
        return [
            OktaUser(
                id="user_001",
                login="john.doe@company.com",
                email="john.doe@company.com",
                first_name="John",
                last_name="Doe",
                display_name="John Doe",
                status=UserStatus.ACTIVE,
                created=datetime.utcnow() - timedelta(days=30),
                type="OKTA_USER",
                group_memberships=["group1", "group2"],
            ),
            OktaUser(
                id="user_002",
                login="jane.smith@company.com",
                email="jane.smith@company.com",
                first_name="Jane",
                last_name="Smith",
                display_name="Jane Smith",
                status=UserStatus.SUSPENDED,
                created=datetime.utcnow() - timedelta(days=60),
                type="OKTA_USER",
                group_memberships=["group1"],
            ),
        ]

    @pytest.fixture
    def sample_groups(self) -> list[OktaGroup]:
        """Create sample groups for testing."""
        return [
            OktaGroup(
                id="group_001",
                name="Administrators",
                description="System administrators",
                type=GroupType.OKTA_GROUP,
                created=datetime.utcnow() - timedelta(days=100),
                members=["user_001", "user_003"],
            ),
            OktaGroup(
                id="group_002",
                name="Developers",
                description="Software developers",
                type=GroupType.APP_GROUP,
                created=datetime.utcnow() - timedelta(days=50),
                members=["user_001", "user_002"],
            ),
        ]

    @pytest.fixture
    def sample_applications(self) -> list[OktaApplication]:
        """Create sample applications for testing."""
        return [
            OktaApplication(
                id="app_001",
                name="Enterprise CRM",
                label="CRM System",
                status=ApplicationStatus.ACTIVE,
                sign_on_mode="SAML_2_0",
                created=datetime.utcnow() - timedelta(days=200),
                features=["SSO", "PROVISIONING"],
                visibility={"hide": {"iOS": False, "web": False}},
            ),
            OktaApplication(
                id="app_002",
                name="HR Portal",
                label="Human Resources",
                status=ApplicationStatus.INACTIVE,
                sign_on_mode="OPENID_CONNECT",
                created=datetime.utcnow() - timedelta(days=150),
                features=["SSO"],
                visibility={"hide": {"iOS": True, "web": False}},
            ),
        ]

    @pytest.mark.asyncio
    async def test_schema_initialization(self, db_manager: DatabaseManager) -> None:
        """Test database schema initialization."""
        # Schema should be initialized by fixture
        info = await db_manager.get_database_info()
        assert info["exists"] is True
        assert "table_counts" in info

    @pytest.mark.asyncio
    async def test_store_and_retrieve_audit_session(
        self,
        db_manager: DatabaseManager,
        sample_audit_session: AuditSession,
    ) -> None:
        """Test storing and retrieving audit sessions."""
        # Store session
        await db_manager.store_audit_session(sample_audit_session)

        # Retrieve session
        retrieved = await db_manager.get_audit_session("session_001")

        assert retrieved is not None
        assert retrieved.session_id == "session_001"
        assert retrieved.status == AuditStatus.COMPLETED
        assert len(retrieved.findings) == 2
        assert retrieved.total_users_analyzed == 100

        # Check findings data
        high_risk_finding = next(
            f for f in retrieved.findings if f.risk_level == RiskLevel.HIGH
        )
        assert high_risk_finding.id == "finding_001"
        assert high_risk_finding.affected_users == ["user1", "user2"]

    @pytest.mark.asyncio
    async def test_list_audit_sessions(
        self,
        db_manager: DatabaseManager,
        sample_audit_session: AuditSession,
    ) -> None:
        """Test listing audit sessions."""
        # Store a session
        await db_manager.store_audit_session(sample_audit_session)

        # List all sessions
        sessions = await db_manager.list_audit_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "session_001"

        # List with status filter
        completed_sessions = await db_manager.list_audit_sessions(
            status_filter=AuditStatus.COMPLETED
        )
        assert len(completed_sessions) == 1

        running_sessions = await db_manager.list_audit_sessions(
            status_filter=AuditStatus.RUNNING
        )
        assert len(running_sessions) == 0

    @pytest.mark.asyncio
    async def test_cache_and_retrieve_users(
        self,
        db_manager: DatabaseManager,
        sample_users: list[OktaUser],
    ) -> None:
        """Test user caching functionality."""
        # Cache users
        await db_manager.cache_users(sample_users, ttl_hours=1)

        # Retrieve cached users
        cached_users = await db_manager.get_cached_users(active_only=False)
        assert len(cached_users) == 2

        # Check data integrity
        john = next(u for u in cached_users if u.login == "john.doe@company.com")
        assert john.first_name == "John"
        assert john.group_memberships == ["group1", "group2"]

        # Test active_only filter
        active_users = await db_manager.get_cached_users(active_only=True)
        assert len(active_users) == 1
        assert active_users[0].status == UserStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_cache_and_retrieve_groups(
        self,
        db_manager: DatabaseManager,
        sample_groups: list[OktaGroup],
    ) -> None:
        """Test group caching functionality."""
        # Cache groups
        await db_manager.cache_groups(sample_groups, ttl_hours=1)

        # Retrieve cached groups
        cached_groups = await db_manager.get_cached_groups()
        assert len(cached_groups) == 2

        # Check data integrity
        admins = next(g for g in cached_groups if g.name == "Administrators")
        assert admins.description == "System administrators"
        assert admins.members == ["user_001", "user_003"]

    @pytest.mark.asyncio
    async def test_cache_and_retrieve_applications(
        self,
        db_manager: DatabaseManager,
        sample_applications: list[OktaApplication],
    ) -> None:
        """Test application caching functionality."""
        # Cache applications
        await db_manager.cache_applications(sample_applications, ttl_hours=1)

        # Retrieve cached applications
        cached_apps = await db_manager.get_cached_applications()
        assert len(cached_apps) == 2

        # Check data integrity
        crm = next(a for a in cached_apps if a.name == "Enterprise CRM")
        assert crm.sign_on_mode == "SAML_2_0"
        assert crm.features == ["SSO", "PROVISIONING"]

    @pytest.mark.asyncio
    async def test_cache_expiration(self, db_manager: DatabaseManager) -> None:
        """Test cache TTL and expiration."""
        # Create a user with very short TTL
        users = [
            OktaUser(
                id="temp_user",
                login="temp@example.com",
                email="temp@example.com",
                first_name="Temp",
                last_name="User",
                display_name="Temp User",
                status=UserStatus.ACTIVE,
                type="OKTA_USER",
            )
        ]

        # Cache with 0 hours TTL (should expire immediately)
        await db_manager.cache_users(users, ttl_hours=0)

        # Should return empty list since cache is expired
        cached_users = await db_manager.get_cached_users()
        assert len(cached_users) == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_cache(
        self,
        db_manager: DatabaseManager,
        sample_users: list[OktaUser],
    ) -> None:
        """Test expired cache cleanup."""
        # Cache users with short TTL
        await db_manager.cache_users(sample_users, ttl_hours=0)

        # Run cleanup
        cleanup_stats = await db_manager.cleanup_expired_cache()

        assert cleanup_stats["users_removed"] == 2
        assert cleanup_stats["groups_removed"] == 0
        assert cleanup_stats["applications_removed"] == 0

    @pytest.mark.asyncio
    async def test_cache_statistics(
        self,
        db_manager: DatabaseManager,
        sample_users: list[OktaUser],
        sample_groups: list[OktaGroup],
    ) -> None:
        """Test cache statistics functionality."""
        # Cache some data
        await db_manager.cache_users(sample_users)
        await db_manager.cache_groups(sample_groups)

        stats = await db_manager.get_cache_statistics()

        assert stats["users"]["total"] == 2
        assert stats["users"]["active"] == 2
        assert stats["groups"]["total"] == 2
        assert stats["groups"]["active"] == 2
        assert stats["applications"]["total"] == 0

    @pytest.mark.asyncio
    async def test_database_transaction(self, db_manager: DatabaseManager) -> None:
        """Test database transaction context manager."""
        # Use transaction context
        async with db_manager.transaction() as db:
            await db.execute("""
                INSERT INTO users_cache (
                    id, login, email, first_name, last_name,
                    display_name, status, type, group_memberships,
                    expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "tx_user",
                "tx@example.com",
                "tx@example.com",
                "Transaction",
                "User",
                "Transaction User",
                "ACTIVE",
                "OKTA_USER",
                "[]",
                (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            ))

        # Verify transaction was committed
        cached_users = await db_manager.get_cached_users()
        assert len(cached_users) == 1
        assert cached_users[0].login == "tx@example.com"

    @pytest.mark.asyncio
    async def test_database_info(self, db_manager: DatabaseManager) -> None:
        """Test database information retrieval."""
        info = await db_manager.get_database_info()

        assert info["exists"] is True
        assert "path" in info
        assert "size_bytes" in info
        assert "modified_at" in info
        assert "table_counts" in info

    @pytest.mark.asyncio
    async def test_vacuum_database(self, db_manager: DatabaseManager) -> None:
        """Test database vacuum operation."""
        # Should complete without errors
        await db_manager.vacuum_database()

    @pytest.mark.asyncio
    async def test_nonexistent_session_retrieval(
        self, db_manager: DatabaseManager
    ) -> None:
        """Test retrieving non-existent audit session."""
        session = await db_manager.get_audit_session("nonexistent_session")
        assert session is None

    @pytest.mark.asyncio
    async def test_session_update(
        self,
        db_manager: DatabaseManager,
        sample_audit_session: AuditSession,
    ) -> None:
        """Test updating existing audit session."""
        # Store initial session
        await db_manager.store_audit_session(sample_audit_session)

        # Update session status
        sample_audit_session.status = AuditStatus.FAILED
        sample_audit_session.errors = ["Connection timeout"]

        # Store updated session
        await db_manager.store_audit_session(sample_audit_session)

        # Retrieve and verify update
        retrieved = await db_manager.get_audit_session("session_001")
        assert retrieved is not None
        assert retrieved.status == AuditStatus.FAILED
        assert retrieved.errors == ["Connection timeout"]

    @pytest.mark.asyncio
    async def test_concurrent_database_access(
        self, db_manager: DatabaseManager
    ) -> None:
        """Test concurrent database operations."""
        import asyncio

        users1 = [
            OktaUser(
                id=f"concurrent_user_{i}",
                login=f"user{i}@example.com",
                email=f"user{i}@example.com",
                first_name=f"User{i}",
                last_name="Test",
                display_name=f"User {i}",
                status=UserStatus.ACTIVE,
                type="OKTA_USER",
            )
            for i in range(1, 6)
        ]

        users2 = [
            OktaUser(
                id=f"concurrent_user_{i}",
                login=f"user{i}@example.com",
                email=f"user{i}@example.com",
                first_name=f"User{i}",
                last_name="Test",
                display_name=f"User {i}",
                status=UserStatus.ACTIVE,
                type="OKTA_USER",
            )
            for i in range(6, 11)
        ]

        # Cache users concurrently
        await asyncio.gather(
            db_manager.cache_users(users1),
            db_manager.cache_users(users2),
        )

        # Verify all users were cached
        cached_users = await db_manager.get_cached_users()
        assert len(cached_users) == 10

    def test_database_error_exception(self) -> None:
        """Test DatabaseError exception."""
        error = DatabaseError("Test database error")
        assert str(error) == "Test database error"
        assert isinstance(error, Exception)

