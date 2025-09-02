"""Tests for policy evaluator functionality."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from opda.models.audit_results import PolicyViolation, RiskLevel
from opda.models.okta_entities import (
    ApplicationStatus,
    GroupType,
    OktaApplication,
    OktaGroup,
    OktaUser,
    UserStatus,
)
from opda.policies.engine import PolicyEngine
from opda.policies.evaluator import PolicyEvaluator


class MockPolicyEngine(PolicyEngine):
    """Mock policy engine for testing."""

    def __init__(self) -> None:
        self.validation_results: dict[str, bool] = {}
        self.evaluation_results: dict[str, dict] = {}

    def set_validation_result(self, policy_content: str, is_valid: bool) -> None:
        """Set validation result for specific policy content."""
        self.validation_results[policy_content] = is_valid

    def set_evaluation_result(self, policy_name: str, result: dict) -> None:
        """Set evaluation result for specific policy."""
        self.evaluation_results[policy_name] = result

    async def validate_policy(self, policy_content: str) -> bool:
        return self.validation_results.get(policy_content, True)

    async def evaluate_policy(
        self,
        policy_content: str,
        input_data: dict,
        policy_name: str | None = None,
    ) -> dict:
        return self.evaluation_results.get(
            policy_name or "default",
            {
                "violations": [],
                "allowed": True,
                "errors": [],
                "policy_name": policy_name,
            }
        )

    async def evaluate_multiple_policies(
        self, policies: dict[str, str], input_data: dict
    ) -> dict[str, dict]:
        results = {}
        for policy_name in policies.keys():
            results[policy_name] = await self.evaluate_policy(
                policies[policy_name], input_data, policy_name
            )
        return results


class TestPolicyEvaluator:
    """Test PolicyEvaluator functionality."""

    @pytest.fixture
    def mock_engine(self) -> MockPolicyEngine:
        """Create mock policy engine."""
        return MockPolicyEngine()

    @pytest.fixture
    def policy_evaluator(self, mock_engine: MockPolicyEngine) -> PolicyEvaluator:
        """Create policy evaluator with mock engine."""
        return PolicyEvaluator(policy_engine=mock_engine)

    @pytest.fixture
    def sample_user(self) -> OktaUser:
        """Create sample user for testing."""
        return OktaUser(
            id="user_001",
            login="john.doe@company.com",
            email="john.doe@company.com",
            first_name="John",
            last_name="Doe",
            display_name="John Doe",
            status=UserStatus.ACTIVE,
            created=datetime.utcnow() - timedelta(days=30),
            type="OKTA_USER",
            group_memberships=["admin", "developers"],
        )

    @pytest.fixture
    def sample_group(self) -> OktaGroup:
        """Create sample group for testing."""
        return OktaGroup(
            id="group_001",
            name="Administrators",
            description="System administrators",
            type=GroupType.OKTA_GROUP,
            created=datetime.utcnow() - timedelta(days=100),
            members=["user_001", "user_002"],
        )

    @pytest.fixture
    def sample_application(self) -> OktaApplication:
        """Create sample application for testing."""
        return OktaApplication(
            id="app_001",
            name="Enterprise CRM",
            label="CRM System",
            status=ApplicationStatus.ACTIVE,
            sign_on_mode="SAML_2_0",
            created=datetime.utcnow() - timedelta(days=200),
            features=["SSO", "PROVISIONING"],
        )

    @pytest.mark.asyncio
    async def test_load_policies_from_directory(
        self, policy_evaluator: PolicyEvaluator, mock_engine: MockPolicyEngine
    ) -> None:
        """Test loading policies from directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir)

            # Create test policy files
            policy1 = policy_dir / "admin_policy.rego"
            policy1.write_text("package admin_policy\nallow = true")

            policy2 = policy_dir / "user_policy.rego"
            policy2.write_text("package user_policy\ndeny = false")

            invalid_policy = policy_dir / "invalid.rego"
            invalid_policy.write_text("invalid rego syntax")

            # Set validation results
            mock_engine.set_validation_result(
                "package admin_policy\nallow = true", True
            )
            mock_engine.set_validation_result("package user_policy\ndeny = false", True)
            mock_engine.set_validation_result("invalid rego syntax", False)

            # Load policies
            loaded = await policy_evaluator.load_policies_from_directory(policy_dir)

            assert len(loaded) == 2
            assert "admin_policy" in loaded
            assert "user_policy" in loaded
            assert "invalid" not in loaded

    @pytest.mark.asyncio
    async def test_load_policies_nonexistent_directory(
        self, policy_evaluator: PolicyEvaluator
    ) -> None:
        """Test loading from non-existent directory."""
        loaded = await policy_evaluator.load_policies_from_directory(
            "/nonexistent/path"
        )
        assert len(loaded) == 0

    @pytest.mark.asyncio
    async def test_evaluate_user_policies_no_violations(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_user: OktaUser,
    ) -> None:
        """Test user policy evaluation with no violations."""
        policies = {
            "user_active": "package user_active\nallow = input.user.status == 'ACTIVE'"
        }

        # Set evaluation result - no violations
        mock_engine.set_evaluation_result("user_active", {
            "violations": [],
            "allowed": True,
            "errors": [],
            "policy_name": "user_active",
        })

        violations = await policy_evaluator.evaluate_user_policies(
            sample_user, policies
        )

        assert len(violations) == 0

    @pytest.mark.asyncio
    async def test_evaluate_user_policies_with_violations(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_user: OktaUser,
    ) -> None:
        """Test user policy evaluation with violations."""
        policies = {
            "admin_check": "package admin_check\ndeny = 'User has admin privileges'"
        }

        # Set evaluation result - with violations
        mock_engine.set_evaluation_result("admin_check", {
            "violations": ["User has excessive admin privileges"],
            "allowed": False,
            "errors": [],
            "policy_name": "admin_check",
        })

        violations = await policy_evaluator.evaluate_user_policies(
            sample_user, policies
        )

        assert len(violations) == 1
        assert isinstance(violations[0], PolicyViolation)
        assert violations[0].policy_name == "admin_check"
        assert violations[0].entity_id == sample_user.id
        assert violations[0].entity_type == "user"

    @pytest.mark.asyncio
    async def test_evaluate_group_policies(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_group: OktaGroup,
    ) -> None:
        """Test group policy evaluation."""
        policies = {
            "group_size": "package group_size\nviolations = ['Too many members']"
        }

        mock_engine.set_evaluation_result("group_size", {
            "violations": ["Group has too many members"],
            "allowed": False,
            "errors": [],
            "policy_name": "group_size",
        })

        violations = await policy_evaluator.evaluate_group_policies(
            sample_group, policies
        )

        assert len(violations) == 1
        assert violations[0].entity_type == "group"
        assert violations[0].entity_id == sample_group.id

    @pytest.mark.asyncio
    async def test_evaluate_application_policies(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_application: OktaApplication,
    ) -> None:
        """Test application policy evaluation."""
        policies = {
            "app_security": "package app_security\nviolations = ['Insecure config']"
        }

        mock_engine.set_evaluation_result("app_security", {
            "violations": ["Application has insecure configuration"],
            "allowed": False,
            "errors": [],
            "policy_name": "app_security",
        })

        violations = await policy_evaluator.evaluate_application_policies(
            sample_application, policies
        )

        assert len(violations) == 1
        assert violations[0].entity_type == "application"
        assert violations[0].entity_id == sample_application.id

    @pytest.mark.asyncio
    async def test_evaluate_bulk_entities(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_user: OktaUser,
        sample_group: OktaGroup,
        sample_application: OktaApplication,
    ) -> None:
        """Test bulk entity evaluation."""
        policies = {"test_policy": "package test\nallow = true"}

        # Set no violations for all evaluations
        mock_engine.set_evaluation_result("test_policy", {
            "violations": [],
            "allowed": True,
            "errors": [],
            "policy_name": "test_policy",
        })

        violations = await policy_evaluator.evaluate_bulk_entities(
            users=[sample_user],
            groups=[sample_group],
            applications=[sample_application],
            policies=policies,
        )

        assert "users" in violations
        assert "groups" in violations
        assert "applications" in violations
        assert len(violations["users"]) == 0
        assert len(violations["groups"]) == 0
        assert len(violations["applications"]) == 0

    @pytest.mark.asyncio
    async def test_evaluate_bulk_entities_with_violations(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_user: OktaUser,
    ) -> None:
        """Test bulk evaluation with violations."""
        policies = {"violation_policy": "package test\ndeny = true"}

        # Set violations for user evaluation
        mock_engine.set_evaluation_result("violation_policy", {
            "violations": ["Policy violation found"],
            "allowed": False,
            "errors": [],
            "policy_name": "violation_policy",
        })

        violations = await policy_evaluator.evaluate_bulk_entities(
            users=[sample_user],
            policies=policies,
        )

        assert len(violations["users"]) == 1
        assert len(violations["groups"]) == 0
        assert len(violations["applications"]) == 0

    def test_create_violations_from_string(
        self, policy_evaluator: PolicyEvaluator, sample_user: OktaUser
    ) -> None:
        """Test creating violations from string violation data."""
        policy_result = {
            "violations": ["Simple violation message"],
            "allowed": False,
            "policy_name": "test_policy",
        }

        violations = policy_evaluator._create_violations_from_result(
            policy_result, sample_user, "test_policy", "user"
        )

        assert len(violations) == 1
        assert violations[0].violation_details == "Simple violation message"
        assert violations[0].policy_name == "test_policy"

    def test_create_violations_from_dict(
        self, policy_evaluator: PolicyEvaluator, sample_user: OktaUser
    ) -> None:
        """Test creating violations from structured violation data."""
        policy_result = {
            "violations": [
                {
                    "rule": "Admin access control",
                    "message": "User has admin access",
                    "severity": "HIGH",
                    "expected": "regular user",
                    "actual": "admin user",
                }
            ],
            "allowed": False,
            "policy_name": "admin_policy",
        }

        violations = policy_evaluator._create_violations_from_result(
            policy_result, sample_user, "admin_policy", "user"
        )

        assert len(violations) == 1
        violation = violations[0]
        assert violation.policy_rule == "Admin access control"
        assert violation.violation_details == "User has admin access"
        assert violation.severity == RiskLevel.HIGH
        assert violation.expected_value == "regular user"
        assert violation.actual_value == "admin user"

    def test_create_violations_allowed_policy(
        self, policy_evaluator: PolicyEvaluator, sample_user: OktaUser
    ) -> None:
        """Test that no violations are created for allowed policies."""
        policy_result = {
            "violations": ["Should be ignored"],
            "allowed": True,  # Policy allows the action
            "policy_name": "allow_policy",
        }

        violations = policy_evaluator._create_violations_from_result(
            policy_result, sample_user, "allow_policy", "user"
        )

        assert len(violations) == 0

    def test_determine_violation_severity(
        self, policy_evaluator: PolicyEvaluator
    ) -> None:
        """Test violation severity determination."""
        # Critical keywords
        assert policy_evaluator._determine_violation_severity(
            "Critical security violation"
        ) == RiskLevel.CRITICAL

        assert policy_evaluator._determine_violation_severity(
            "Admin privilege escalation detected"
        ) == RiskLevel.CRITICAL

        # High keywords
        assert policy_evaluator._determine_violation_severity(
            "High risk unauthorized access"
        ) == RiskLevel.HIGH

        # Medium keywords
        assert policy_evaluator._determine_violation_severity(
            "Medium priority warning"
        ) == RiskLevel.MEDIUM

        # Default to low
        assert policy_evaluator._determine_violation_severity(
            "Simple notification"
        ) == RiskLevel.LOW

    def test_parse_severity(self, policy_evaluator: PolicyEvaluator) -> None:
        """Test severity string parsing."""
        assert policy_evaluator._parse_severity("CRITICAL") == RiskLevel.CRITICAL
        assert policy_evaluator._parse_severity("high") == RiskLevel.HIGH
        assert policy_evaluator._parse_severity("Medium") == RiskLevel.MEDIUM
        assert policy_evaluator._parse_severity("low") == RiskLevel.LOW

        # Unknown severity defaults to medium
        assert policy_evaluator._parse_severity("unknown") == RiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_validate_all_policies(
        self, policy_evaluator: PolicyEvaluator, mock_engine: MockPolicyEngine
    ) -> None:
        """Test validation of all loaded policies."""
        policies = {
            "valid_policy": "package valid\nallow = true",
            "invalid_policy": "invalid syntax here",
        }

        # Set validation results
        mock_engine.set_validation_result("package valid\nallow = true", True)
        mock_engine.set_validation_result("invalid syntax here", False)

        # Add policies to evaluator
        for name, content in policies.items():
            policy_evaluator.add_policy(name, content)

        results = await policy_evaluator.validate_all_policies()

        assert results["valid_policy"] is True
        assert results["invalid_policy"] is False

    def test_policy_management(self, policy_evaluator: PolicyEvaluator) -> None:
        """Test policy management operations."""
        # Add policy
        policy_evaluator.add_policy("test_policy", "package test\nallow = true")
        assert len(policy_evaluator.get_loaded_policies()) == 1

        # Remove policy
        removed = policy_evaluator.remove_policy("test_policy")
        assert removed is True
        assert len(policy_evaluator.get_loaded_policies()) == 0

        # Try to remove non-existent policy
        removed = policy_evaluator.remove_policy("nonexistent")
        assert removed is False

        # Clear policies
        policy_evaluator.add_policy("policy1", "content1")
        policy_evaluator.add_policy("policy2", "content2")
        assert len(policy_evaluator.get_loaded_policies()) == 2

        policy_evaluator.clear_policies()
        assert len(policy_evaluator.get_loaded_policies()) == 0

    def test_evaluator_stats(self, policy_evaluator: PolicyEvaluator) -> None:
        """Test evaluator statistics."""
        policy_evaluator.add_policy("test1", "content1")
        policy_evaluator.add_policy("test2", "content2")

        stats = policy_evaluator.get_evaluator_stats()

        assert stats["loaded_policies"] == 2
        assert "test1" in stats["policy_names"]
        assert "test2" in stats["policy_names"]
        assert "engine_type" in stats

    @pytest.mark.asyncio
    async def test_evaluate_policies_no_policies_loaded(
        self, policy_evaluator: PolicyEvaluator, sample_user: OktaUser
    ) -> None:
        """Test evaluation when no policies are loaded."""
        violations = await policy_evaluator.evaluate_user_policies(sample_user)
        assert len(violations) == 0

    @pytest.mark.asyncio
    async def test_evaluate_with_context_data(
        self,
        policy_evaluator: PolicyEvaluator,
        mock_engine: MockPolicyEngine,
        sample_user: OktaUser,
    ) -> None:
        """Test evaluation with additional context data."""
        policies = {"context_policy": "package test\nallow = true"}
        context = {
            "environment": "production",
            "timestamp": datetime.utcnow().isoformat(),
        }

        mock_engine.set_evaluation_result("context_policy", {
            "violations": [],
            "allowed": True,
            "errors": [],
            "policy_name": "context_policy",
        })

        violations = await policy_evaluator.evaluate_user_policies(
            sample_user, policies, context
        )

        assert len(violations) == 0

    def test_create_violations_with_unknown_format(
        self, policy_evaluator: PolicyEvaluator, sample_user: OktaUser
    ) -> None:
        """Test handling of unknown violation data format."""
        policy_result = {
            "violations": [42, True, None],  # Unknown formats
            "allowed": False,
            "policy_name": "weird_policy",
        }

        violations = policy_evaluator._create_violations_from_result(
            policy_result, sample_user, "weird_policy", "user"
        )

        # Should create violations for each item, even if format is unknown
        assert len(violations) == 3
        for violation in violations:
            assert violation.policy_name == "weird_policy"
            assert violation.entity_id == sample_user.id

