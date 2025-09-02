"""
Open Policy Agent (OPA) integration for Rego policy evaluation.

Provides a Python interface to OPA for evaluating Rego policies
against Okta entity data and generating policy violations.
"""

import json
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class PolicyError(Exception):
    """Base exception for policy evaluation errors."""

    def __init__(self, message: str, policy_file: str | None = None) -> None:
        super().__init__(message)
        self.policy_file = policy_file


class PolicyEngine(ABC):
    """Abstract base class for policy evaluation engines."""

    @abstractmethod
    async def evaluate_policy(
        self,
        policy_content: str,
        input_data: dict[str, Any],
        policy_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate a policy against input data.

        Args:
            policy_content: The policy content (e.g., Rego code)
            input_data: Data to evaluate against the policy
            policy_name: Optional name for the policy

        Returns:
            Policy evaluation result
        """

    @abstractmethod
    async def validate_policy(self, policy_content: str) -> bool:
        """
        Validate policy syntax without evaluation.

        Args:
            policy_content: The policy content to validate

        Returns:
            True if policy is valid, False otherwise
        """


class OPAEngine(PolicyEngine):
    """
    Open Policy Agent integration for Rego policy evaluation.

    Provides methods to evaluate Rego policies using the OPA binary,
    with support for batch evaluation and policy validation.
    """

    def __init__(self, opa_binary_path: str | Path = "opa") -> None:
        self.opa_binary_path = Path(opa_binary_path)
        self._opa_available: bool | None = None

        logger.info("OPA engine initialized", opa_path=str(self.opa_binary_path))

    async def is_opa_available(self) -> bool:
        """Check if OPA binary is available and functional."""
        if self._opa_available is not None:
            return self._opa_available

        try:
            result = subprocess.run(
                [str(self.opa_binary_path), "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._opa_available = result.returncode == 0

            if self._opa_available:
                logger.info("OPA binary available", version=result.stdout.strip())
            else:
                logger.warning("OPA binary not available or not functional")

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("Failed to check OPA availability", error=str(e))
            self._opa_available = False

        return self._opa_available

    async def validate_policy(self, policy_content: str) -> bool:
        """
        Validate Rego policy syntax using OPA.

        Args:
            policy_content: Rego policy content

        Returns:
            True if policy is syntactically valid
        """
        if not await self.is_opa_available():
            raise PolicyError("OPA binary not available")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rego", delete=False
        ) as temp_policy:
            temp_policy.write(policy_content)
            temp_policy.flush()

            try:
                result = subprocess.run(
                    [str(self.opa_binary_path), "fmt", temp_policy.name],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                is_valid = result.returncode == 0

                if not is_valid:
                    logger.warning(
                        "Policy validation failed",
                        error=result.stderr,
                        returncode=result.returncode,
                    )

                return is_valid

            except subprocess.TimeoutExpired:
                logger.error("Policy validation timed out")
                return False
            finally:
                Path(temp_policy.name).unlink(missing_ok=True)

    async def evaluate_policy(
        self,
        policy_content: str,
        input_data: dict[str, Any],
        policy_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate a Rego policy against input data using OPA.

        Args:
            policy_content: Rego policy content
            input_data: Data to evaluate against policy
            policy_name: Optional policy identifier

        Returns:
            Policy evaluation results

        Raises:
            PolicyError: If evaluation fails
        """
        if not await self.is_opa_available():
            raise PolicyError("OPA binary not available")

        # Validate policy first
        if not await self.validate_policy(policy_content):
            raise PolicyError(f"Invalid policy syntax: {policy_name or 'unnamed'}")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)

            # Write policy file
            policy_file = temp_dir_path / "policy.rego"
            policy_file.write_text(policy_content, encoding="utf-8")

            # Write input data file
            input_file = temp_dir_path / "input.json"
            input_file.write_text(json.dumps(input_data), encoding="utf-8")

            try:
                # Run OPA eval command
                result = subprocess.run(
                    [
                        str(self.opa_binary_path),
                        "eval",
                        "-d",
                        str(policy_file),
                        "-i",
                        str(input_file),
                        "--format",
                        "json",
                        "data",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.returncode != 0:
                    error_msg = f"Policy evaluation failed: {result.stderr}"
                    logger.error(
                        "OPA evaluation error",
                        policy_name=policy_name,
                        error=result.stderr,
                        returncode=result.returncode,
                    )
                    raise PolicyError(error_msg, policy_name)

                # Parse OPA output
                try:
                    opa_output = json.loads(result.stdout)
                    return self._process_opa_output(opa_output, policy_name)

                except json.JSONDecodeError as e:
                    logger.error("Failed to parse OPA output", error=str(e))
                    raise PolicyError(f"Invalid OPA output format: {e}") from e

            except subprocess.TimeoutExpired:
                error_msg = f"Policy evaluation timed out: {policy_name or 'unnamed'}"
                logger.error("Policy evaluation timeout", policy_name=policy_name)
                raise PolicyError(error_msg) from None

    def _process_opa_output(
        self, opa_output: dict[str, Any], policy_name: str | None
    ) -> dict[str, Any]:
        """
        Process raw OPA output into structured results.

        Args:
            opa_output: Raw output from OPA eval command
            policy_name: Policy identifier for logging

        Returns:
            Processed evaluation results
        """
        try:
            # OPA eval returns a list of results
            if not isinstance(opa_output, dict) or "result" not in opa_output:
                logger.warning("Unexpected OPA output format", output=opa_output)
                return {
                    "violations": [],
                    "allowed": True,
                    "errors": ["Unexpected output format"],
                }

            result = opa_output["result"]

            # Handle different OPA result formats
            if isinstance(result, list) and result:
                result = result[0]  # Take first result

            if not isinstance(result, dict):
                return {"violations": [], "allowed": True, "errors": []}

            # Extract common policy result patterns
            violations = []
            allowed = True
            errors = []
            details = {}

            # Check for standard policy patterns
            for key, value in result.items():
                if key in ["violations", "deny", "errors"]:
                    if isinstance(value, list):
                        if key == "violations":
                            violations.extend(value)
                        elif key == "deny":
                            violations.extend(value)
                            allowed = False
                        elif key == "errors":
                            errors.extend(value)
                    elif value:  # Non-empty value
                        if key in ["deny"]:
                            allowed = False
                            if isinstance(value, str):
                                violations.append(value)
                elif key == "allow":
                    allowed = bool(value)
                else:
                    # Store other policy-specific data
                    details[key] = value

            logger.debug(
                "Policy evaluation completed",
                policy_name=policy_name,
                violations_count=len(violations),
                allowed=allowed,
                errors_count=len(errors),
            )

            return {
                "violations": violations,
                "allowed": allowed,
                "errors": errors,
                "details": details,
                "policy_name": policy_name,
            }

        except Exception as e:
            logger.error(
                "Failed to process OPA output",
                policy_name=policy_name,
                error=str(e),
                output=opa_output,
            )
            return {
                "violations": [],
                "allowed": True,
                "errors": [f"Processing error: {e}"],
                "policy_name": policy_name,
            }

    async def evaluate_multiple_policies(
        self,
        policies: dict[str, str],
        input_data: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """
        Evaluate multiple policies against the same input data.

        Args:
            policies: Dictionary of policy_name -> policy_content
            input_data: Data to evaluate against all policies

        Returns:
            Dictionary of policy_name -> evaluation_result
        """
        results = {}

        for policy_name, policy_content in policies.items():
            try:
                result = await self.evaluate_policy(
                    policy_content, input_data, policy_name
                )
                results[policy_name] = result

            except PolicyError as e:
                logger.error(
                    "Policy evaluation failed",
                    policy_name=policy_name,
                    error=str(e),
                )
                results[policy_name] = {
                    "violations": [],
                    "allowed": True,
                    "errors": [str(e)],
                    "policy_name": policy_name,
                }

        logger.info(
            "Multiple policy evaluation completed",
            total_policies=len(policies),
            successful_evaluations=sum(
                1 for r in results.values() if not r.get("errors", [])
            ),
        )

        return results

    async def test_policy_with_examples(
        self,
        policy_content: str,
        test_cases: list[dict[str, Any]],
        policy_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Test a policy against multiple example inputs.

        Args:
            policy_content: Rego policy content
            test_cases: List of test input data
            policy_name: Policy identifier

        Returns:
            Test results summary
        """
        results = []

        for i, test_input in enumerate(test_cases):
            try:
                result = await self.evaluate_policy(
                    policy_content, test_input, f"{policy_name}_test_{i}"
                )
                results.append({
                    "test_case": i,
                    "input": test_input,
                    "result": result,
                    "success": True,
                })

            except PolicyError as e:
                results.append({
                    "test_case": i,
                    "input": test_input,
                    "error": str(e),
                    "success": False,
                })

        successful_tests = sum(1 for r in results if r["success"])

        return {
            "policy_name": policy_name,
            "total_tests": len(test_cases),
            "successful_tests": successful_tests,
            "failed_tests": len(test_cases) - successful_tests,
            "results": results,
        }

    def get_engine_info(self) -> dict[str, Any]:
        """Get information about the OPA engine setup."""
        return {
            "engine_type": "OPA",
            "opa_binary_path": str(self.opa_binary_path),
            "opa_available": self._opa_available,
        }

