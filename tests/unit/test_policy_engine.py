"""Tests for policy engine functionality."""

import json
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from opda.policies.engine import OPAEngine, PolicyEngine, PolicyError


class MockPolicyEngine(PolicyEngine):
    """Mock policy engine for testing."""

    def __init__(self) -> None:
        self.policies_validated: list[str] = []
        self.evaluations_performed: list[dict] = []

    async def evaluate_policy(
        self,
        policy_content: str,
        input_data: dict,
        policy_name: str | None = None,
    ) -> dict:
        self.evaluations_performed.append({
            "policy_content": policy_content,
            "input_data": input_data,
            "policy_name": policy_name,
        })

        # Simple mock evaluation logic
        if "deny" in policy_content.lower():
            return {
                "violations": ["Mock violation detected"],
                "allowed": False,
                "errors": [],
                "policy_name": policy_name,
            }

        return {
            "violations": [],
            "allowed": True,
            "errors": [],
            "policy_name": policy_name,
        }

    async def validate_policy(self, policy_content: str) -> bool:
        self.policies_validated.append(policy_content)
        # Mock validation - fail if contains "invalid"
        return "invalid" not in policy_content.lower()


class TestPolicyEngine:
    """Test abstract PolicyEngine base class."""

    @pytest.mark.asyncio
    async def test_mock_policy_engine(self) -> None:
        """Test mock policy engine implementation."""
        engine = MockPolicyEngine()

        # Test policy validation
        valid_policy = "package test\nallow = true"
        assert await engine.validate_policy(valid_policy) is True

        invalid_policy = "invalid policy content"
        assert await engine.validate_policy(invalid_policy) is False

        # Test policy evaluation
        result = await engine.evaluate_policy(
            valid_policy,
            {"user": {"id": "test_user"}},
            "test_policy"
        )

        assert result["allowed"] is True
        assert len(result["violations"]) == 0
        assert result["policy_name"] == "test_policy"


class TestOPAEngine:
    """Test OPA engine implementation."""

    @pytest.fixture
    def opa_engine(self) -> OPAEngine:
        """Create OPA engine for testing."""
        return OPAEngine(opa_binary_path="mock_opa")

    @pytest.mark.asyncio
    async def test_opa_availability_check_success(self, opa_engine: OPAEngine) -> None:
        """Test successful OPA availability check."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Open Policy Agent 0.45.0"

        with patch("subprocess.run", return_value=mock_result):
            is_available = await opa_engine.is_opa_available()
            assert is_available is True
            assert opa_engine._opa_available is True

    @pytest.mark.asyncio
    async def test_opa_availability_check_failure(self, opa_engine: OPAEngine) -> None:
        """Test failed OPA availability check."""
        with patch("subprocess.run", side_effect=FileNotFoundError("opa not found")):
            is_available = await opa_engine.is_opa_available()
            assert is_available is False
            assert opa_engine._opa_available is False

    @pytest.mark.asyncio
    async def test_validate_policy_success(self, opa_engine: OPAEngine) -> None:
        """Test successful policy validation."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            opa_engine._opa_available = True
            policy_content = "package test\nallow = true"

            is_valid = await opa_engine.validate_policy(policy_content)
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_policy_failure(self, opa_engine: OPAEngine) -> None:
        """Test failed policy validation."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "syntax error"

        with patch("subprocess.run", return_value=mock_result):
            opa_engine._opa_available = True
            invalid_policy = "invalid rego syntax"

            is_valid = await opa_engine.validate_policy(invalid_policy)
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_policy_opa_unavailable(self, opa_engine: OPAEngine) -> None:
        """Test policy validation when OPA is unavailable."""
        opa_engine._opa_available = False

        with pytest.raises(PolicyError, match="OPA binary not available"):
            await opa_engine.validate_policy("package test")

    @pytest.mark.asyncio
    async def test_evaluate_policy_success(self, opa_engine: OPAEngine) -> None:
        """Test successful policy evaluation."""
        # Mock successful validation
        validation_result = Mock()
        validation_result.returncode = 0

        # Mock successful evaluation
        eval_result = Mock()
        eval_result.returncode = 0
        eval_result.stdout = json.dumps({
            "result": {
                "allow": True,
                "violations": []
            }
        })

        with patch("subprocess.run", side_effect=[validation_result, eval_result]):
            opa_engine._opa_available = True

            policy_content = "package test\nallow = true"
            input_data = {"user": {"id": "test_user"}}

            result = await opa_engine.evaluate_policy(
                policy_content, input_data, "test_policy"
            )

            assert result["allowed"] is True
            assert result["policy_name"] == "test_policy"
            assert len(result["violations"]) == 0

    @pytest.mark.asyncio
    async def test_evaluate_policy_with_violations(self, opa_engine: OPAEngine) -> None:
        """Test policy evaluation that produces violations."""
        # Mock validation
        validation_result = Mock()
        validation_result.returncode = 0

        # Mock evaluation with violations
        eval_result = Mock()
        eval_result.returncode = 0
        eval_result.stdout = json.dumps({
            "result": {
                "deny": ["Access denied", "Insufficient privileges"],
                "violations": ["Test violation"]
            }
        })

        with patch("subprocess.run", side_effect=[validation_result, eval_result]):
            opa_engine._opa_available = True

            policy_content = "package test\ndeny = ['Access denied']"
            input_data = {"user": {"id": "bad_user"}}

            result = await opa_engine.evaluate_policy(
                policy_content, input_data, "deny_policy"
            )

            assert result["allowed"] is False
            assert len(result["violations"]) == 3  # deny + violations

    @pytest.mark.asyncio
    async def test_evaluate_policy_opa_error(self, opa_engine: OPAEngine) -> None:
        """Test policy evaluation with OPA error."""
        # Mock validation success
        validation_result = Mock()
        validation_result.returncode = 0

        # Mock evaluation failure
        eval_result = Mock()
        eval_result.returncode = 1
        eval_result.stderr = "evaluation error"

        with patch("subprocess.run", side_effect=[validation_result, eval_result]):
            opa_engine._opa_available = True

            with pytest.raises(PolicyError, match="Policy evaluation failed"):
                await opa_engine.evaluate_policy(
                    "package test", {"data": "test"}, "error_policy"
                )

    @pytest.mark.asyncio
    async def test_evaluate_policy_invalid_syntax(self, opa_engine: OPAEngine) -> None:
        """Test evaluation of policy with invalid syntax."""
        # Mock validation failure
        validation_result = Mock()
        validation_result.returncode = 1

        with patch("subprocess.run", return_value=validation_result):
            opa_engine._opa_available = True

            with pytest.raises(PolicyError, match="Invalid policy syntax"):
                await opa_engine.evaluate_policy(
                    "invalid syntax", {"data": "test"}, "invalid_policy"
                )

    @pytest.mark.asyncio
    async def test_evaluate_multiple_policies(self, opa_engine: OPAEngine) -> None:
        """Test evaluation of multiple policies."""
        policies = {
            "policy1": "package policy1\nallow = true",
            "policy2": "package policy2\ndeny = ['violation']",
        }

        # Mock results for each policy evaluation
        def mock_evaluate_policy(policy_content, input_data, policy_name):
            if "deny" in policy_content:
                return {
                    "violations": ["violation"],
                    "allowed": False,
                    "errors": [],
                    "policy_name": policy_name,
                }
            return {
                "violations": [],
                "allowed": True,
                "errors": [],
                "policy_name": policy_name,
            }

        opa_engine.evaluate_policy = AsyncMock(side_effect=mock_evaluate_policy)

        results = await opa_engine.evaluate_multiple_policies(
            policies, {"user": {"id": "test"}}
        )

        assert len(results) == 2
        assert results["policy1"]["allowed"] is True
        assert results["policy2"]["allowed"] is False
        assert len(results["policy2"]["violations"]) == 1

    @pytest.mark.asyncio
    async def test_test_policy_with_examples(self, opa_engine: OPAEngine) -> None:
        """Test policy testing with multiple examples."""
        policy_content = "package test\nallow = input.user.active"
        test_cases = [
            {"user": {"active": True, "id": "user1"}},
            {"user": {"active": False, "id": "user2"}},
            {"user": {"active": True, "id": "user3"}},
        ]

        # Mock evaluation results
        def mock_evaluate(policy, data, name):
            if data["user"]["active"]:
                return {"allowed": True, "violations": []}
            return {"allowed": False, "violations": ["User not active"]}

        opa_engine.evaluate_policy = AsyncMock(side_effect=mock_evaluate)

        results = await opa_engine.test_policy_with_examples(
            policy_content, test_cases, "active_user_policy"
        )

        assert results["total_tests"] == 3
        assert results["successful_tests"] == 3
        assert results["failed_tests"] == 0
        assert len(results["results"]) == 3

    @pytest.mark.asyncio
    async def test_test_policy_with_error(self, opa_engine: OPAEngine) -> None:
        """Test policy testing with evaluation errors."""
        policy_content = "invalid policy"
        test_cases = [{"user": {"id": "test"}}]

        opa_engine.evaluate_policy = AsyncMock(
            side_effect=PolicyError("Evaluation failed")
        )

        results = await opa_engine.test_policy_with_examples(
            policy_content, test_cases, "error_policy"
        )

        assert results["total_tests"] == 1
        assert results["successful_tests"] == 0
        assert results["failed_tests"] == 1
        assert not results["results"][0]["success"]

    def test_opa_engine_info(self, opa_engine: OPAEngine) -> None:
        """Test engine information retrieval."""
        info = opa_engine.get_engine_info()

        assert info["engine_type"] == "OPA"
        assert info["opa_binary_path"] == "mock_opa"
        assert "opa_available" in info

    def test_process_opa_output_basic(self, opa_engine: OPAEngine) -> None:
        """Test basic OPA output processing."""
        opa_output = {
            "result": {
                "allow": True,
                "violations": []
            }
        }

        result = opa_engine._process_opa_output(opa_output, "test_policy")

        assert result["allowed"] is True
        assert result["policy_name"] == "test_policy"
        assert len(result["violations"]) == 0

    def test_process_opa_output_with_violations(self, opa_engine: OPAEngine) -> None:
        """Test OPA output processing with violations."""
        opa_output = {
            "result": {
                "deny": ["Access denied"],
                "violations": ["Policy violation"],
                "details": {"reason": "insufficient privileges"}
            }
        }

        result = opa_engine._process_opa_output(opa_output, "security_policy")

        assert result["allowed"] is False
        assert len(result["violations"]) == 2  # deny + violations
        assert result["details"]["reason"] == "insufficient privileges"

    def test_process_opa_output_invalid_format(self, opa_engine: OPAEngine) -> None:
        """Test OPA output processing with invalid format."""
        opa_output = {"invalid": "format"}

        result = opa_engine._process_opa_output(opa_output, "test_policy")

        assert result["allowed"] is True
        assert len(result["violations"]) == 0
        assert len(result["errors"]) == 1

    def test_process_opa_output_list_result(self, opa_engine: OPAEngine) -> None:
        """Test OPA output processing with list result format."""
        opa_output = {
            "result": [{
                "allow": False,
                "violations": ["Test violation"]
            }]
        }

        result = opa_engine._process_opa_output(opa_output, "list_policy")

        assert result["allowed"] is False
        assert len(result["violations"]) == 1

    @pytest.mark.asyncio
    async def test_evaluate_policy_timeout(self, opa_engine: OPAEngine) -> None:
        """Test policy evaluation timeout handling."""
        # Mock validation success
        validation_result = Mock()
        validation_result.returncode = 0

        with patch("subprocess.run", side_effect=[
            validation_result,  # Validation
subprocess.TimeoutExpired("opa", 60)  # Evaluation timeout
        ]):
            opa_engine._opa_available = True

            with pytest.raises(PolicyError, match="timed out"):
                await opa_engine.evaluate_policy(
                    "package test", {"data": "test"}, "timeout_policy"
                )

    @pytest.mark.asyncio
    async def test_validate_policy_timeout(self, opa_engine: OPAEngine) -> None:
        """Test policy validation timeout handling."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("opa", 30)
        ):
            opa_engine._opa_available = True

            is_valid = await opa_engine.validate_policy("package test")
            assert is_valid is False


def test_policy_error_exception() -> None:
    """Test PolicyError exception."""
    error = PolicyError("Test error", "test_policy.rego")
    assert str(error) == "Test error"
    assert error.policy_file == "test_policy.rego"

    # Test without policy file
    error2 = PolicyError("Another error")
    assert error2.policy_file is None

