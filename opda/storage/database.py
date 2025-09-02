"""
SQLite database storage for audit sessions and caching.

Provides persistent storage for audit results, session tracking,
and caching of Okta entity data to support offline analysis.
"""

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite
import structlog

from opda.models.audit_results import AuditSession, AuditStatus
from opda.models.okta_entities import OktaApplication, OktaGroup, OktaUser

logger = structlog.get_logger(__name__)


class DatabaseError(Exception):
    """Base exception for database operations."""


class DatabaseManager:
    """
    SQLite database manager for OPDA audit data and caching.

    Handles audit session persistence, entity caching, and
    provides transactional operations with proper error handling.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._ensure_directory_exists()

        logger.info("Database manager initialized", db_path=str(self.db_path))

    def _ensure_directory_exists(self) -> None:
        """Ensure the database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def initialize_schema(self) -> None:
        """Initialize database schema with all required tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Enable foreign key constraints
            await db.execute("PRAGMA foreign_keys = ON")

            # Create audit sessions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_sessions (
                    session_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    audit_scope JSON NOT NULL,
                    policies_evaluated JSON,
                    total_users_analyzed INTEGER DEFAULT 0,
                    total_groups_analyzed INTEGER DEFAULT 0,
                    total_applications_analyzed INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    errors JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create audit findings table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_findings (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_users JSON,
                    affected_groups JSON,
                    affected_applications JSON,
                    violated_policies JSON,
                    remediation_required BOOLEAN DEFAULT FALSE,
                    remediation_priority INTEGER,
                    recommended_actions JSON,
                    discovered_at TIMESTAMP NOT NULL,
                    resolved_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES audit_sessions (session_id)
                        ON DELETE CASCADE
                )
            """)

            # Create entity cache tables
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users_cache (
                    id TEXT PRIMARY KEY,
                    login TEXT UNIQUE NOT NULL,
                    email TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    display_name TEXT,
                    status TEXT NOT NULL,
                    created TIMESTAMP,
                    activated TIMESTAMP,
                    last_login TIMESTAMP,
                    last_updated TIMESTAMP,
                    password_changed TIMESTAMP,
                    type TEXT,
                    group_memberships JSON,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS groups_cache (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    type TEXT NOT NULL,
                    created TIMESTAMP,
                    last_updated TIMESTAMP,
                    last_membership_updated TIMESTAMP,
                    members JSON,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS applications_cache (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    label TEXT,
                    status TEXT NOT NULL,
                    sign_on_mode TEXT,
                    created TIMESTAMP,
                    last_updated TIMESTAMP,
                    features JSON,
                    visibility JSON,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)

            # Create indexes for performance
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_findings_session
                ON audit_findings (session_id)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_findings_risk_level
                ON audit_findings (risk_level)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_cache_expires
                ON users_cache (expires_at)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_groups_cache_expires
                ON groups_cache (expires_at)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_applications_cache_expires
                ON applications_cache (expires_at)
            """)

            # Create trigger to update updated_at timestamp
            await db.execute("""
                CREATE TRIGGER IF NOT EXISTS update_audit_sessions_updated_at
                AFTER UPDATE ON audit_sessions
                BEGIN
                    UPDATE audit_sessions
                    SET updated_at = CURRENT_TIMESTAMP
                    WHERE session_id = NEW.session_id;
                END
            """)

            await db.commit()

        logger.info("Database schema initialized successfully")

    async def store_audit_session(self, session: AuditSession) -> None:
        """Store or update an audit session."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO audit_sessions (
                    session_id, status, started_at, completed_at,
                    audit_scope, policies_evaluated,
                    total_users_analyzed, total_groups_analyzed,
                    total_applications_analyzed, total_findings, errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                session.status.value,
                session.started_at.isoformat(),
                session.completed_at.isoformat() if session.completed_at else None,
                json.dumps(session.audit_scope),
                json.dumps(session.policies_evaluated),
                session.total_users_analyzed,
                session.total_groups_analyzed,
                session.total_applications_analyzed,
                len(session.findings),
                json.dumps(session.errors),
            ))

            # Store findings
            for finding in session.findings:
                await db.execute("""
                    INSERT OR REPLACE INTO audit_findings (
                        id, session_id, finding_type, risk_level,
                        title, description, affected_users, affected_groups,
                        affected_applications, violated_policies,
                        remediation_required, remediation_priority,
                        recommended_actions, discovered_at, resolved_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.id,
                    session.session_id,
                    finding.finding_type.value,
                    finding.risk_level.value,
                    finding.title,
                    finding.description,
                    json.dumps(finding.affected_users),
                    json.dumps(finding.affected_groups),
                    json.dumps(finding.affected_applications),
                    json.dumps(finding.violated_policies),
                    finding.remediation_required,
                    finding.remediation_priority,
                    json.dumps(finding.recommended_actions),
                    finding.discovered_at.isoformat(),
                    finding.resolved_at.isoformat() if finding.resolved_at else None,
                ))

            await db.commit()

        logger.info("Audit session stored", session_id=session.session_id)

    async def get_audit_session(self, session_id: str) -> AuditSession | None:
        """Retrieve an audit session by ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Get session data
            async with db.execute("""
                SELECT * FROM audit_sessions WHERE session_id = ?
            """, (session_id,)) as cursor:
                session_row = await cursor.fetchone()

            if not session_row:
                return None

            # Get findings for this session
            findings = []
            async with db.execute("""
                SELECT * FROM audit_findings WHERE session_id = ?
                ORDER BY discovered_at DESC
            """, (session_id,)) as cursor:
                async for finding_row in cursor:
                    finding_data = dict(finding_row)
                    finding_data["finding_type"] = finding_data["finding_type"]
                    finding_data["risk_level"] = finding_data["risk_level"]
                    finding_data["affected_users"] = json.loads(
                        finding_data["affected_users"] or "[]"
                    )
                    finding_data["affected_groups"] = json.loads(
                        finding_data["affected_groups"] or "[]"
                    )
                    finding_data["affected_applications"] = json.loads(
                        finding_data["affected_applications"] or "[]"
                    )
                    finding_data["violated_policies"] = json.loads(
                        finding_data["violated_policies"] or "[]"
                    )
                    finding_data["recommended_actions"] = json.loads(
                        finding_data["recommended_actions"] or "[]"
                    )

                    # Remove database-specific fields
                    finding_data.pop("created_at", None)

                    findings.append(finding_data)

            # Build session data
            session_data = dict(session_row)
            session_data["status"] = AuditStatus(session_data["status"])
            session_data["audit_scope"] = json.loads(session_data["audit_scope"])
            session_data["policies_evaluated"] = json.loads(
                session_data["policies_evaluated"] or "[]"
            )
            session_data["errors"] = json.loads(session_data["errors"] or "[]")
            session_data["findings"] = findings

            # Remove database-specific fields
            session_data.pop("created_at", None)
            session_data.pop("updated_at", None)
            session_data.pop("total_findings", None)

            return AuditSession(**session_data)

    async def list_audit_sessions(
        self,
        limit: int = 50,
        status_filter: AuditStatus | None = None,
    ) -> list[dict[str, Any]]:
        """List audit sessions with optional filtering."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            query = """
                SELECT session_id, status, started_at, completed_at,
                       total_users_analyzed, total_groups_analyzed,
                       total_applications_analyzed, total_findings
                FROM audit_sessions
            """
            params = []

            if status_filter:
                query += " WHERE status = ?"
                params.append(status_filter.value)

            query += " ORDER BY started_at DESC LIMIT ?"
            params.append(limit)

            sessions = []
            async with db.execute(query, params) as cursor:
                async for row in cursor:
                    sessions.append(dict(row))

            logger.debug("Listed audit sessions", count=len(sessions))
            return sessions

    async def cache_users(self, users: list[OktaUser], ttl_hours: int = 24) -> None:
        """Cache user data with TTL."""
        expires_at = datetime.utcnow().replace(microsecond=0) + \
                    __import__('datetime').timedelta(hours=ttl_hours)

        async with aiosqlite.connect(self.db_path) as db:
            for user in users:
                await db.execute("""
                    INSERT OR REPLACE INTO users_cache (
                        id, login, email, first_name, last_name, display_name,
                        status, created, activated, last_login, last_updated,
                        password_changed, type, group_memberships, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.id,
                    user.login,
                    user.email,
                    user.first_name,
                    user.last_name,
                    user.display_name,
                    user.status.value,
                    user.created.isoformat() if user.created else None,
                    user.activated.isoformat() if user.activated else None,
                    user.last_login.isoformat() if user.last_login else None,
                    user.last_updated.isoformat() if user.last_updated else None,
                    (
                        user.password_changed.isoformat()
                        if user.password_changed
                        else None
                    ),
                    user.type,
                    json.dumps(user.group_memberships),
                    expires_at.isoformat(),
                ))

            await db.commit()

        logger.info("Users cached", count=len(users), ttl_hours=ttl_hours)

    async def get_cached_users(self, active_only: bool = True) -> list[OktaUser]:
        """Retrieve cached users that haven't expired."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            query = """
                SELECT * FROM users_cache
                WHERE expires_at > datetime('now')
            """
            params = []

            if active_only:
                query += " AND status = ?"
                params.append("ACTIVE")

            users = []
            async with db.execute(query, params) as cursor:
                async for row in cursor:
                    user_data = dict(row)

                    # Convert JSON fields back
                    user_data["group_memberships"] = json.loads(
                        user_data["group_memberships"] or "[]"
                    )

                    # Remove cache-specific fields
                    user_data.pop("cached_at", None)
                    user_data.pop("expires_at", None)

                    # Convert timestamps back to datetime objects
                    timestamp_fields = [
                        "created", "activated", "last_login",
                        "last_updated", "password_changed"
                    ]
                    for field in timestamp_fields:
                        if user_data[field]:
                            user_data[field] = datetime.fromisoformat(user_data[field])

                    users.append(OktaUser(**user_data))

            logger.debug("Retrieved cached users", count=len(users))
            return users

    async def cache_groups(self, groups: list[OktaGroup], ttl_hours: int = 24) -> None:
        """Cache group data with TTL."""
        expires_at = datetime.utcnow().replace(microsecond=0) + \
                    __import__('datetime').timedelta(hours=ttl_hours)

        async with aiosqlite.connect(self.db_path) as db:
            for group in groups:
                await db.execute("""
                    INSERT OR REPLACE INTO groups_cache (
                        id, name, description, type, created, last_updated,
                        last_membership_updated, members, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    group.id,
                    group.name,
                    group.description,
                    group.type.value,
                    group.created.isoformat() if group.created else None,
                    group.last_updated.isoformat() if group.last_updated else None,
                    (
                        group.last_membership_updated.isoformat()
                        if group.last_membership_updated
                        else None
                    ),
                    json.dumps(group.members),
                    expires_at.isoformat(),
                ))

            await db.commit()

        logger.info("Groups cached", count=len(groups), ttl_hours=ttl_hours)

    async def get_cached_groups(self) -> list[OktaGroup]:
        """Retrieve cached groups that haven't expired."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            groups = []
            async with db.execute("""
                SELECT * FROM groups_cache
                WHERE expires_at > datetime('now')
            """) as cursor:
                async for row in cursor:
                    group_data = dict(row)

                    # Convert JSON fields back
                    group_data["members"] = json.loads(group_data["members"] or "[]")

                    # Remove cache-specific fields
                    group_data.pop("cached_at", None)
                    group_data.pop("expires_at", None)

                    # Convert timestamps back to datetime objects
                    group_timestamp_fields = [
                        "created", "last_updated", "last_membership_updated"
                    ]
                    for field in group_timestamp_fields:
                        if group_data[field]:
                            group_data[field] = datetime.fromisoformat(
                                group_data[field]
                            )

                    groups.append(OktaGroup(**group_data))

            logger.debug("Retrieved cached groups", count=len(groups))
            return groups

    async def cache_applications(
        self, apps: list[OktaApplication], ttl_hours: int = 24
    ) -> None:
        """Cache application data with TTL."""
        expires_at = datetime.utcnow().replace(microsecond=0) + \
                    __import__('datetime').timedelta(hours=ttl_hours)

        async with aiosqlite.connect(self.db_path) as db:
            for app in apps:
                await db.execute("""
                    INSERT OR REPLACE INTO applications_cache (
                        id, name, label, status, sign_on_mode,
                        created, last_updated, features, visibility, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    app.id,
                    app.name,
                    app.label,
                    app.status.value,
                    app.sign_on_mode,
                    app.created.isoformat() if app.created else None,
                    app.last_updated.isoformat() if app.last_updated else None,
                    json.dumps(app.features),
                    json.dumps(app.visibility),
                    expires_at.isoformat(),
                ))

            await db.commit()

        logger.info("Applications cached", count=len(apps), ttl_hours=ttl_hours)

    async def get_cached_applications(self) -> list[OktaApplication]:
        """Retrieve cached applications that haven't expired."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            apps = []
            async with db.execute("""
                SELECT * FROM applications_cache
                WHERE expires_at > datetime('now')
            """) as cursor:
                async for row in cursor:
                    app_data = dict(row)

                    # Convert JSON fields back
                    app_data["features"] = json.loads(app_data["features"] or "[]")
                    app_data["visibility"] = json.loads(app_data["visibility"] or "{}")

                    # Remove cache-specific fields
                    app_data.pop("cached_at", None)
                    app_data.pop("expires_at", None)

                    # Convert timestamps back to datetime objects
                    for field in ["created", "last_updated"]:
                        if app_data[field]:
                            app_data[field] = datetime.fromisoformat(app_data[field])

                    apps.append(OktaApplication(**app_data))

            logger.debug("Retrieved cached applications", count=len(apps))
            return apps

    async def cleanup_expired_cache(self) -> dict[str, int]:
        """Remove expired cache entries and return cleanup statistics."""
        async with aiosqlite.connect(self.db_path) as db:
            cleanup_stats = {}

            # Clean up expired users
            cursor = await db.execute("""
                DELETE FROM users_cache WHERE expires_at <= datetime('now')
            """)
            cleanup_stats["users_removed"] = cursor.rowcount

            # Clean up expired groups
            cursor = await db.execute("""
                DELETE FROM groups_cache WHERE expires_at <= datetime('now')
            """)
            cleanup_stats["groups_removed"] = cursor.rowcount

            # Clean up expired applications
            cursor = await db.execute("""
                DELETE FROM applications_cache WHERE expires_at <= datetime('now')
            """)
            cleanup_stats["applications_removed"] = cursor.rowcount

            await db.commit()

        logger.info("Cache cleanup completed", **cleanup_stats)
        return cleanup_stats

    async def get_cache_statistics(self) -> dict[str, Any]:
        """Get cache usage statistics."""
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}

            # Count cached entities
            cursor = await db.execute("""
                SELECT
                    COUNT(*) as total_users,
                    COUNT(
                        CASE WHEN expires_at > datetime('now') THEN 1 END
                    ) as active_users
                FROM users_cache
            """)
            row = await cursor.fetchone()
            stats["users"] = {"total": row[0], "active": row[1]}

            cursor = await db.execute("""
                SELECT
                    COUNT(*) as total_groups,
                    COUNT(
                        CASE WHEN expires_at > datetime('now') THEN 1 END
                    ) as active_groups
                FROM groups_cache
            """)
            row = await cursor.fetchone()
            stats["groups"] = {"total": row[0], "active": row[1]}

            cursor = await db.execute("""
                SELECT
                    COUNT(*) as total_apps,
                    COUNT(
                        CASE WHEN expires_at > datetime('now') THEN 1 END
                    ) as active_apps
                FROM applications_cache
            """)
            row = await cursor.fetchone()
            stats["applications"] = {"total": row[0], "active": row[1]}

            # Count audit sessions
            cursor = await db.execute("""
                SELECT COUNT(*) FROM audit_sessions
            """)
            row = await cursor.fetchone()
            stats["audit_sessions"] = row[0]

            # Count total findings
            cursor = await db.execute("""
                SELECT COUNT(*) FROM audit_findings
            """)
            row = await cursor.fetchone()
            stats["total_findings"] = row[0]

            return stats

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Provide a database transaction context manager."""
        async with aiosqlite.connect(self.db_path) as db:
            try:
                await db.execute("BEGIN")
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    async def vacuum_database(self) -> None:
        """Optimize database storage by running VACUUM."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("VACUUM")

        logger.info("Database vacuumed successfully")

    async def get_database_info(self) -> dict[str, Any]:
        """Get database file information and statistics."""
        if not self.db_path.exists():
            return {"exists": False}

        stat = self.db_path.stat()

        async with aiosqlite.connect(self.db_path) as db:
            # Get table sizes
            cursor = await db.execute("""
                SELECT name, COUNT(*) as row_count
                FROM (
                    SELECT 'audit_sessions' as name, session_id FROM audit_sessions
                    UNION ALL
                    SELECT 'audit_findings' as name, id FROM audit_findings
                    UNION ALL
                    SELECT 'users_cache' as name, id FROM users_cache
                    UNION ALL
                    SELECT 'groups_cache' as name, id FROM groups_cache
                    UNION ALL
                    SELECT 'applications_cache' as name, id FROM applications_cache
                ) tables
                GROUP BY name
            """)

            table_counts = {}
            async for row in cursor:
                table_counts[row[0]] = row[1]

        return {
            "exists": True,
            "path": str(self.db_path),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "table_counts": table_counts,
        }

