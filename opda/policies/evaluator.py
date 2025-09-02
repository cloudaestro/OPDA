"""
High-level policy evaluator for OPDA audit operations.

Coordinates policy evaluation across multiple Okta entities,
generates policy violations, and manages policy loading.
"""

from pathlib import Path
from typing import Any

import structlog

from opda.models.audit_results import PolicyViolation, RiskLevel
from opda.models.okta_entities import OktaApplication, OktaGroup, OktaUser
from opda.policies.engine import OPAEngine, PolicyEngine

logger = structlog.get_logger(__name__)


class PolicyEvaluator:
    """
    High-level policy evaluator for OPDA audit operations.

    Manages policy loading, entity evaluation, and violation generation
    using the configured policy engine backend.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        policy_directory: Path | str | None = None,
    ) -> None:
        self.policy_engine = policy_engine or OPAEngine()
        self.policy_directory = Path(policy_directory) if policy_directory else None
        self._loaded_policies: dict[str, str] = {}

        logger.info(
            "Policy evaluator initialized",
            engine_type=type(self.policy_engine).__name__,
            policy_directory=(
                str(self.policy_directory) if self.policy_directory else None
            ),
        )

    async def load_policies_from_directory(
        self, directory: Path | str | None = None
    ) -> dict[str, str]:
        """
        Load all Rego policy files from a directory.

        Args:
            directory: Directory containing .rego files (uses default if None)

        Returns:
            Dictionary of policy_name -> policy_content
        """
        policy_dir = Path(directory) if directory else self.policy_directory

        if not policy_dir or not policy_dir.exists():
            logger.warning(
                "Policy directory not found",
                directory=str(policy_dir) if policy_dir else None,
            )
            return {}

        policies = {}

        for policy_file in policy_dir.glob("*.rego"):
            try:
                policy_name = policy_file.stem
                policy_content = policy_file.read_text(encoding="utf-8")

                # Validate policy syntax
                if await self.policy_engine.validate_policy(policy_content):
                    policies[policy_name] = policy_content
                    logger.debug(
                        "Policy loaded successfully",
                        policy_name=policy_name,
                        file_path=str(policy_file),
                    )
                else:
                    logger.warning(
                        "Invalid policy syntax, skipping",
                        policy_name=policy_name,
                        file_path=str(policy_file),
                    )

            except Exception as e:
                logger.error(
                    "Failed to load policy file",
                    file_path=str(policy_file),
                    error=str(e),
                )

        self._loaded_policies.update(policies)

        logger.info(
            "Policy loading completed",
            directory=str(policy_dir),
            policies_loaded=len(policies),
            total_policies=len(self._loaded_policies),
        )

        return policies

    async def evaluate_user_policies(
        self,
        user: OktaUser,
        policies: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[PolicyViolation]:
        """
        Evaluate policies against a specific user.

        Args:
            user: User to evaluate
            policies: Policies to evaluate (uses loaded policies if None)
            context: Additional context data for evaluation

        Returns:
            List of policy violations found
        """
        evaluation_policies = policies or self._loaded_policies

        if not evaluation_policies:
            logger.warning("No policies available for evaluation")
            return []

        # Prepare input data for policy evaluation
        input_data = {
            "user": user.model_dump(),
            "context": context or {},
            "entity_type": "user",
        }

        violations = []

        # Evaluate each policy against the user
        results = await self.policy_engine.evaluate_multiple_policies(
            evaluation_policies, input_data
        )

        for policy_name, result in results.items():
            violations.extend(
                self._create_violations_from_result(
                    result, user, policy_name, "user"
                )
            )

        logger.debug(
            "User policy evaluation completed",
            user_id=user.id,
            policies_evaluated=len(evaluation_policies),
            violations_found=len(violations),
        )

        return violations

    async def evaluate_group_policies(
        self,
        group: OktaGroup,
        policies: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[PolicyViolation]:
        """
        Evaluate policies against a specific group.

        Args:
            group: Group to evaluate
            policies: Policies to evaluate (uses loaded policies if None)
            context: Additional context data for evaluation

        Returns:
            List of policy violations found
        """
        evaluation_policies = policies or self._loaded_policies

        if not evaluation_policies:
            logger.warning("No policies available for evaluation")
            return []

        input_data = {
            "group": group.model_dump(),
            "context": context or {},
            "entity_type": "group",
        }

        violations = []

        results = await self.policy_engine.evaluate_multiple_policies(
            evaluation_policies, input_data
        )

        for policy_name, result in results.items():
            violations.extend(
                self._create_violations_from_result(
                    result, group, policy_name, "group"
                )
            )

        logger.debug(
            "Group policy evaluation completed",
            group_id=group.id,
            policies_evaluated=len(evaluation_policies),
            violations_found=len(violations),
        )

        return violations

    async def evaluate_application_policies(
        self,
        application: OktaApplication,
        policies: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[PolicyViolation]:
        """
        Evaluate policies against a specific application.

        Args:
            application: Application to evaluate
            policies: Policies to evaluate (uses loaded policies if None)
            context: Additional context data for evaluation

        Returns:
            List of policy violations found
        """
        evaluation_policies = policies or self._loaded_policies

        if not evaluation_policies:
            logger.warning("No policies available for evaluation")
            return []

        input_data = {
            "application": application.model_dump(),
            "context": context or {},
            "entity_type": "application",
        }

        violations = []

        results = await self.policy_engine.evaluate_multiple_policies(
            evaluation_policies, input_data
        )

        for policy_name, result in results.items():
            violations.extend(
                self._create_violations_from_result(
                    result, application, policy_name, "application"
                )
            )

        logger.debug(
            "Application policy evaluation completed",
            application_id=application.id,
            policies_evaluated=len(evaluation_policies),
            violations_found=len(violations),
        )

        return violations

    async def evaluate_bulk_entities(
        self,
        users: list[OktaUser] | None = None,
        groups: list[OktaGroup] | None = None,
        applications: list[OktaApplication] | None = None,
        policies: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, list[PolicyViolation]]:
        """
        Evaluate policies against multiple entities in bulk.

        Args:
            users: Users to evaluate
            groups: Groups to evaluate
            applications: Applications to evaluate
            policies: Policies to use (uses loaded policies if None)
            context: Additional context data

        Returns:
            Dictionary of entity_type -> list of violations
        """
        all_violations: dict[str, list[PolicyViolation]] = {
            "users": [],
            "groups": [],
            "applications": [],
        }

        # Evaluate users
        if users:
            for user in users:
                violations = await self.evaluate_user_policies(user, policies, context)
                all_violations["users"].extend(violations)

        # Evaluate groups
        if groups:
            for group in groups:
                violations = await self.evaluate_group_policies(
                    group, policies, context
                )
                all_violations["groups"].extend(violations)

        # Evaluate applications
        if applications:
            for application in applications:
                violations = await self.evaluate_application_policies(
                    application, policies, context
                )
                all_violations["applications"].extend(violations)

        total_violations = sum(len(v) for v in all_violations.values())

        logger.info(
            "Bulk policy evaluation completed",
            users_evaluated=len(users) if users else 0,
            groups_evaluated=len(groups) if groups else 0,
            applications_evaluated=len(applications) if applications else 0,
            total_violations=total_violations,
        )

        return all_violations

    def _create_violations_from_result(
        self,
        policy_result: dict[str, Any],
        entity: OktaUser | OktaGroup | OktaApplication,
        policy_name: str,
        entity_type: str,
    ) -> list[PolicyViolation]:
        """
        Create PolicyViolation objects from policy evaluation results.

        Args:
            policy_result: Result from policy evaluation
            entity: The entity that was evaluated
            policy_name: Name of the policy
            entity_type: Type of entity (user, group, application)

        Returns:
            List of PolicyViolation objects
        """
        violations = []

        # Skip if no violations or policy allowed the entity
        policy_violations = policy_result.get("violations", [])
        if not policy_violations or policy_result.get("allowed", True):
            return violations

        # Handle single violation string
        if isinstance(policy_violations, str):
            policy_violations = [policy_violations]

        # Create violation objects
        for violation_data in policy_violations:
            try:
                if isinstance(violation_data, str):
                    # Simple string violation
                    violation = PolicyViolation(
                        policy_name=policy_name,
                        policy_rule="See policy file for details",
                        violation_details=violation_data,
                        entity_type=entity_type,
                        entity_id=entity.id,
                        entity_name=getattr(entity, "display_name", None)
                                   or getattr(entity, "name", None)
                                   or getattr(entity, "label", None)
                                   or entity.id,
                        severity=self._determine_violation_severity(violation_data),
                    )
                elif isinstance(violation_data, dict):
                    # Structured violation data
                    violation = PolicyViolation(
                        policy_name=policy_name,
                        policy_rule=violation_data.get("rule", "See policy file"),
                        violation_details=violation_data.get(
                            "message", "Policy violation"
                        ),
                        entity_type=entity_type,
                        entity_id=entity.id,
                        entity_name=violation_data.get("entity_name")
                                   or getattr(entity, "display_name", None)
                                   or getattr(entity, "name", None)
                                   or getattr(entity, "label", None)
                                   or entity.id,
                        severity=self._parse_severity(
                            violation_data.get("severity", "MEDIUM")
                        ),
                        expected_value=violation_data.get("expected"),
                        actual_value=violation_data.get("actual"),
                    )
                else:
                    # Unknown format, create basic violation
                    violation = PolicyViolation(
                        policy_name=policy_name,
                        policy_rule="See policy file for details",
                        violation_details=f"Policy violation: {violation_data}",
                        entity_type=entity_type,
                        entity_id=entity.id,
                        entity_name=getattr(entity, "display_name", None)
                                   or getattr(entity, "name", None)
                                   or getattr(entity, "label", None)
                                   or entity.id,
                        severity=RiskLevel.MEDIUM,
                    )

                violations.append(violation)

            except Exception as e:
                logger.warning(
                    "Failed to create violation object",
                    policy_name=policy_name,
                    entity_id=entity.id,
                    violation_data=violation_data,
                    error=str(e),
                )

        return violations

    def _determine_violation_severity(self, violation_message: str) -> RiskLevel:
        """Determine severity level based on violation message content."""
        message_lower = violation_message.lower()

        if any(keyword in message_lower for keyword in [
            "critical", "admin", "privilege", "escalation", "security"
        ]):
            return RiskLevel.CRITICAL
        elif any(keyword in message_lower for keyword in [
            "high", "sensitive", "unauthorized", "breach"
        ]):
            return RiskLevel.HIGH
        elif any(keyword in message_lower for keyword in [
            "medium", "warning", "unusual", "suspicious"
        ]):
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _parse_severity(self, severity_str: str) -> RiskLevel:
        """Parse severity string into RiskLevel enum."""
        try:
            return RiskLevel(severity_str.upper())
        except ValueError:
            logger.warning(
                "Unknown severity level, defaulting to MEDIUM",
                severity=severity_str,
            )
            return RiskLevel.MEDIUM

    async def validate_all_policies(
        self, policies: dict[str, str] | None = None
    ) -> dict[str, bool]:
        """
        Validate syntax of all policies.

        Args:
            policies: Policies to validate (uses loaded policies if None)

        Returns:
            Dictionary of policy_name -> is_valid
        """
        validation_policies = policies or self._loaded_policies

        if not validation_policies:
            logger.warning("No policies to validate")
            return {}

        results = {}

        for policy_name, policy_content in validation_policies.items():
            try:
                is_valid = await self.policy_engine.validate_policy(policy_content)
                results[policy_name] = is_valid

                if not is_valid:
                    logger.warning(
                        "Policy validation failed",
                        policy_name=policy_name,
                    )
                else:
                    logger.debug(
                        "Policy validation successful",
                        policy_name=policy_name,
                    )

            except Exception as e:
                logger.error(
                    "Policy validation error",
                    policy_name=policy_name,
                    error=str(e),
                )
                results[policy_name] = False

        valid_count = sum(results.values())

        logger.info(
            "Policy validation completed",
            total_policies=len(validation_policies),
            valid_policies=valid_count,
            invalid_policies=len(validation_policies) - valid_count,
        )

        return results

    def get_loaded_policies(self) -> dict[str, str]:
        """Get currently loaded policies."""
        return self._loaded_policies.copy()

    def add_policy(self, policy_name: str, policy_content: str) -> None:
        """
        Add a policy to the loaded policies.

        Args:
            policy_name: Name/identifier for the policy
            policy_content: Rego policy content
        """
        self._loaded_policies[policy_name] = policy_content
        logger.debug("Policy added", policy_name=policy_name)

    def remove_policy(self, policy_name: str) -> bool:
        """
        Remove a policy from loaded policies.

        Args:
            policy_name: Name of policy to remove

        Returns:
            True if policy was removed, False if not found
        """
        if policy_name in self._loaded_policies:
            del self._loaded_policies[policy_name]
            logger.debug("Policy removed", policy_name=policy_name)
            return True
        return False

    def clear_policies(self) -> None:
        """Clear all loaded policies."""
        policy_count = len(self._loaded_policies)
        self._loaded_policies.clear()
        logger.info("All policies cleared", previous_count=policy_count)

    def get_evaluator_stats(self) -> dict[str, Any]:
        """Get policy evaluator statistics."""
        return {
            "loaded_policies": len(self._loaded_policies),
            "policy_names": list(self._loaded_policies.keys()),
            "policy_directory": (
                str(self.policy_directory) if self.policy_directory else None
            ),
            "engine_type": type(self.policy_engine).__name__,
        }

