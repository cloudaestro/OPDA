"""
Audit results and drift detection data models.

Contains models for representing audit findings, risk assessments,
and privilege drift analysis results.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level enumeration for audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    """Types of audit findings."""

    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    STALE_ACCESS = "STALE_ACCESS"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ORPHANED_ACCOUNT = "ORPHANED_ACCOUNT"
    EXCESSIVE_PERMISSIONS = "EXCESSIVE_PERMISSIONS"
    MISSING_CONTROLS = "MISSING_CONTROLS"
    CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"


class AuditStatus(str, Enum):
    """Status of audit execution."""

    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AuditFinding(BaseModel):
    """Individual audit finding with risk assessment."""

    id: str = Field(..., description="Unique finding ID")
    finding_type: FindingType = Field(..., description="Type of finding")
    risk_level: RiskLevel = Field(..., description="Risk level assessment")

    title: str = Field(..., description="Brief finding title")
    description: str = Field(..., description="Detailed finding description")

    # Affected entities
    affected_users: list[str] = Field(
        default_factory=list, description="List of affected user IDs"
    )
    affected_groups: list[str] = Field(
        default_factory=list, description="List of affected group IDs"
    )
    affected_applications: list[str] = Field(
        default_factory=list, description="List of affected application IDs"
    )
    affected_roles: list[str] = Field(
        default_factory=list, description="List of affected role IDs"
    )

    # Policy and compliance context
    violated_policies: list[str] = Field(
        default_factory=list, description="List of violated policy names"
    )
    compliance_frameworks: list[str] = Field(
        default_factory=list, description="Relevant compliance frameworks"
    )

    # Evidence and metadata
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Supporting evidence data"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    # Timestamps
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow, description="Finding discovery timestamp"
    )

    # Remediation information
    remediation_required: bool = Field(
        default=False, description="Whether remediation is required"
    )
    remediation_priority: int = Field(
        default=1, ge=1, le=5, description="Remediation priority (1=highest)"
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Recommended remediation actions"
    )

    def get_total_affected_entities(self) -> int:
        """Get total count of affected entities."""
        return (
            len(self.affected_users) +
            len(self.affected_groups) +
            len(self.affected_applications) +
            len(self.affected_roles)
        )

    def is_high_risk(self) -> bool:
        """Check if this is a high or critical risk finding."""
        return self.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def requires_immediate_action(self) -> bool:
        """Check if finding requires immediate attention."""
        return (
            self.risk_level == RiskLevel.CRITICAL or
            (self.risk_level == RiskLevel.HIGH and self.remediation_required)
        )


class PolicyViolation(BaseModel):
    """Specific policy violation details."""

    policy_name: str = Field(..., description="Name of violated policy")
    policy_rule: str = Field(..., description="Specific rule that was violated")
    violation_details: str = Field(..., description="Details of the violation")

    # Context
    entity_type: str = Field(..., description="Type of entity (user, group, app, role)")
    entity_id: str = Field(..., description="ID of the violating entity")
    entity_name: str | None = Field(
        default=None, description="Name of the violating entity"
    )

    # Violation severity
    severity: RiskLevel = Field(..., description="Violation severity")

    # Timestamps
    violation_detected_at: datetime = Field(
        default_factory=datetime.utcnow, description="When violation was detected"
    )

    # Additional context
    expected_value: str | None = Field(
        default=None, description="Expected value per policy"
    )
    actual_value: str | None = Field(
        default=None, description="Actual value found"
    )


class DriftAnalysis(BaseModel):
    """Analysis of privilege drift over time."""

    analysis_id: str = Field(..., description="Unique analysis ID")
    baseline_timestamp: datetime = Field(
        ..., description="Baseline comparison timestamp"
    )
    current_timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Current analysis timestamp"
    )

    # Drift statistics
    new_users: int = Field(default=0, description="Number of new users")
    removed_users: int = Field(default=0, description="Number of removed users")
    modified_users: int = Field(default=0, description="Number of modified users")

    new_groups: int = Field(default=0, description="Number of new groups")
    removed_groups: int = Field(default=0, description="Number of removed groups")
    modified_groups: int = Field(default=0, description="Number of modified groups")

    new_applications: int = Field(default=0, description="Number of new applications")
    removed_applications: int = Field(
        default=0, description="Number of removed applications"
    )
    modified_applications: int = Field(
        default=0, description="Number of modified applications"
    )

    # Permission changes
    privilege_escalations: int = Field(
        default=0, description="Number of privilege escalations"
    )
    privilege_reductions: int = Field(
        default=0, description="Number of privilege reductions"
    )

    # Drift details
    significant_changes: list[dict[str, Any]] = Field(
        default_factory=list, description="List of significant changes"
    )

    def get_total_changes(self) -> int:
        """Get total number of changes detected."""
        return (
            self.new_users + self.removed_users + self.modified_users +
            self.new_groups + self.removed_groups + self.modified_groups +
            self.new_applications + self.removed_applications +
            self.modified_applications
        )

    def get_net_privilege_change(self) -> int:
        """Get net privilege change (positive = escalation, negative = reduction)."""
        return self.privilege_escalations - self.privilege_reductions

    def has_significant_drift(self, threshold_percentage: float = 5.0) -> bool:
        """Check if drift exceeds significance threshold."""
        # This is a simplified implementation - would need baseline counts in practice
        total_changes = self.get_total_changes()
        return total_changes > 0  # Placeholder logic


class AuditSession(BaseModel):
    """Complete audit session with all results."""

    session_id: str = Field(..., description="Unique audit session ID")
    status: AuditStatus = Field(..., description="Audit execution status")

    # Timestamps
    started_at: datetime = Field(..., description="Audit start timestamp")
    completed_at: datetime | None = Field(
        default=None, description="Audit completion timestamp"
    )

    # Configuration
    audit_scope: dict[str, Any] = Field(
        default_factory=dict, description="Audit scope configuration"
    )
    policies_evaluated: list[str] = Field(
        default_factory=list, description="List of policies that were evaluated"
    )

    # Results
    findings: list[AuditFinding] = Field(
        default_factory=list, description="List of audit findings"
    )
    policy_violations: list[PolicyViolation] = Field(
        default_factory=list, description="List of policy violations"
    )
    drift_analysis: DriftAnalysis | None = Field(
        default=None, description="Privilege drift analysis results"
    )

    # Statistics
    total_users_analyzed: int = Field(default=0, description="Total users analyzed")
    total_groups_analyzed: int = Field(default=0, description="Total groups analyzed")
    total_applications_analyzed: int = Field(
        default=0, description="Total applications analyzed"
    )
    total_roles_analyzed: int = Field(default=0, description="Total roles analyzed")

    # Error tracking
    errors: list[str] = Field(
        default_factory=list, description="List of errors encountered"
    )
    warnings: list[str] = Field(
        default_factory=list, description="List of warnings generated"
    )

    def get_duration_seconds(self) -> int | None:
        """Get audit duration in seconds."""
        if not self.completed_at:
            return None
        return int((self.completed_at - self.started_at).total_seconds())

    def get_findings_by_risk_level(self, risk_level: RiskLevel) -> list[AuditFinding]:
        """Get all findings of a specific risk level."""
        return [f for f in self.findings if f.risk_level == risk_level]

    def get_critical_findings_count(self) -> int:
        """Get count of critical findings."""
        return len(self.get_findings_by_risk_level(RiskLevel.CRITICAL))

    def get_high_risk_findings_count(self) -> int:
        """Get count of high risk findings."""
        return len(self.get_findings_by_risk_level(RiskLevel.HIGH))

    def requires_immediate_attention(self) -> bool:
        """Check if audit results require immediate attention."""
        return (
            self.get_critical_findings_count() > 0 or 
            self.get_high_risk_findings_count() > 5
        )

    def is_successful(self) -> bool:
        """Check if audit completed successfully."""
        return self.status == AuditStatus.COMPLETED and len(self.errors) == 0
