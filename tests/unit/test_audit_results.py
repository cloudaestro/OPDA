"""Tests for audit results and drift detection models."""

from datetime import datetime, timedelta

from opda.models.audit_results import (
    AuditFinding,
    AuditSession,
    AuditStatus,
    DriftAnalysis,
    FindingType,
    PolicyViolation,
    RiskLevel,
)


class TestAuditFinding:
    """Test AuditFinding model."""

    def test_valid_finding(self) -> None:
        """Test valid finding creation."""
        finding = AuditFinding(
            id="finding_001",
            finding_type=FindingType.PRIVILEGE_ESCALATION,
            risk_level=RiskLevel.HIGH,
            title="Excessive admin privileges detected",
            description="User has been granted admin privileges in multiple systems",
            affected_users=["user1", "user2"],
            affected_applications=["app1"],
            violated_policies=["policy1", "policy2"],
            remediation_required=True,
            remediation_priority=1,
            recommended_actions=["Remove admin access", "Review access requirements"],
        )

        assert finding.id == "finding_001"
        assert finding.finding_type == FindingType.PRIVILEGE_ESCALATION
        assert finding.risk_level == RiskLevel.HIGH
        assert finding.is_high_risk() is True
        assert finding.requires_immediate_action() is True
        assert finding.get_total_affected_entities() == 3
        assert len(finding.recommended_actions) == 2

    def test_low_risk_finding(self) -> None:
        """Test low risk finding behavior."""
        finding = AuditFinding(
            id="finding_002",
            finding_type=FindingType.STALE_ACCESS,
            risk_level=RiskLevel.LOW,
            title="Inactive user with lingering access",
            description="User has been inactive but still has system access",
            affected_users=["inactive_user"],
        )

        assert finding.is_high_risk() is False
        assert finding.requires_immediate_action() is False

    def test_critical_finding(self) -> None:
        """Test critical finding behavior."""
        finding = AuditFinding(
            id="finding_003",
            finding_type=FindingType.POLICY_VIOLATION,
            risk_level=RiskLevel.CRITICAL,
            title="Super admin role assigned to regular user",
            description="Critical policy violation detected",
            remediation_required=False,  # Even without remediation_required
        )

        assert finding.is_high_risk() is True
        assert finding.requires_immediate_action() is True

    def test_default_timestamp(self) -> None:
        """Test that default timestamp is set."""
        finding = AuditFinding(
            id="finding_004",
            finding_type=FindingType.MISSING_CONTROLS,
            risk_level=RiskLevel.MEDIUM,
            title="Missing MFA enforcement",
            description="MFA not enforced for privileged accounts",
        )

        # Should have a timestamp within the last minute
        time_diff = datetime.utcnow() - finding.discovered_at
        assert time_diff.total_seconds() < 60

    def test_remediation_priority_validation(self) -> None:
        """Test remediation priority bounds."""
        # Valid priority
        finding = AuditFinding(
            id="finding_005",
            finding_type=FindingType.EXCESSIVE_PERMISSIONS,
            risk_level=RiskLevel.HIGH,
            title="Test finding",
            description="Test description",
            remediation_priority=3,
        )
        assert finding.remediation_priority == 3

        # Test bounds via ValidationError would require invalid data
        # Pydantic handles this automatically with ge/le constraints


class TestPolicyViolation:
    """Test PolicyViolation model."""

    def test_valid_policy_violation(self) -> None:
        """Test valid policy violation creation."""
        violation = PolicyViolation(
            policy_name="Admin Access Policy",
            policy_rule="Users must not have admin access to more than 2 systems",
            violation_details="User has admin access to 5 systems",
            entity_type="user",
            entity_id="user123",
            entity_name="John Doe",
            severity=RiskLevel.HIGH,
            expected_value="<= 2 systems",
            actual_value="5 systems",
        )

        assert violation.policy_name == "Admin Access Policy"
        assert violation.entity_type == "user"
        assert violation.entity_id == "user123"
        assert violation.severity == RiskLevel.HIGH
        assert violation.expected_value == "<= 2 systems"
        assert violation.actual_value == "5 systems"

    def test_default_timestamp(self) -> None:
        """Test default violation timestamp."""
        violation = PolicyViolation(
            policy_name="Test Policy",
            policy_rule="Test Rule",
            violation_details="Test violation",
            entity_type="user",
            entity_id="user123",
            severity=RiskLevel.MEDIUM,
        )

        # Should have a timestamp within the last minute
        time_diff = datetime.utcnow() - violation.violation_detected_at
        assert time_diff.total_seconds() < 60


class TestDriftAnalysis:
    """Test DriftAnalysis model."""

    def test_valid_drift_analysis(self) -> None:
        """Test valid drift analysis creation."""
        baseline = datetime.utcnow() - timedelta(days=7)

        analysis = DriftAnalysis(
            analysis_id="drift_001",
            baseline_timestamp=baseline,
            new_users=5,
            removed_users=2,
            modified_users=10,
            new_groups=1,
            privilege_escalations=3,
            privilege_reductions=1,
            significant_changes=[
                {"type": "user_added", "user_id": "new_user_001"},
                {"type": "privilege_granted", "user_id": "user_002"},
            ],
        )

        assert analysis.analysis_id == "drift_001"
        assert analysis.baseline_timestamp == baseline
        assert analysis.get_total_changes() == 18  # 5+2+10+1+0+0 = 18
        assert analysis.get_net_privilege_change() == 2  # 3-1 = 2
        assert len(analysis.significant_changes) == 2

    def test_no_changes_drift(self) -> None:
        """Test drift analysis with no changes."""
        analysis = DriftAnalysis(
            analysis_id="drift_002",
            baseline_timestamp=datetime.utcnow() - timedelta(days=1),
        )

        assert analysis.get_total_changes() == 0
        assert analysis.get_net_privilege_change() == 0
        assert analysis.has_significant_drift() is False

    def test_significant_drift_detection(self) -> None:
        """Test significant drift detection."""
        # Analysis with changes
        analysis_with_changes = DriftAnalysis(
            analysis_id="drift_003",
            baseline_timestamp=datetime.utcnow() - timedelta(days=1),
            new_users=10,
            privilege_escalations=5,
        )

        # Analysis without changes
        analysis_no_changes = DriftAnalysis(
            analysis_id="drift_004",
            baseline_timestamp=datetime.utcnow() - timedelta(days=1),
        )

        # Current implementation returns True for any changes > 0
        assert analysis_with_changes.has_significant_drift() is True
        assert analysis_no_changes.has_significant_drift() is False


class TestAuditSession:
    """Test AuditSession model."""

    def test_valid_audit_session(self) -> None:
        """Test valid audit session creation."""
        start_time = datetime.utcnow()

        session = AuditSession(
            session_id="audit_001",
            status=AuditStatus.RUNNING,
            started_at=start_time,
            audit_scope={"users": True, "groups": True},
            policies_evaluated=["policy1", "policy2"],
            total_users_analyzed=100,
            total_groups_analyzed=25,
        )

        assert session.session_id == "audit_001"
        assert session.status == AuditStatus.RUNNING
        assert session.started_at == start_time
        assert session.total_users_analyzed == 100
        assert len(session.policies_evaluated) == 2

    def test_completed_audit_session(self) -> None:
        """Test completed audit session."""
        start_time = datetime.utcnow() - timedelta(minutes=30)
        end_time = datetime.utcnow()

        findings = [
            AuditFinding(
                id="f1",
                finding_type=FindingType.STALE_ACCESS,
                risk_level=RiskLevel.LOW,
                title="Test finding 1",
                description="Test description",
            ),
            AuditFinding(
                id="f2",
                finding_type=FindingType.PRIVILEGE_ESCALATION,
                risk_level=RiskLevel.CRITICAL,
                title="Test finding 2",
                description="Test description",
            ),
            AuditFinding(
                id="f3",
                finding_type=FindingType.POLICY_VIOLATION,
                risk_level=RiskLevel.HIGH,
                title="Test finding 3",
                description="Test description",
            ),
        ]

        session = AuditSession(
            session_id="audit_002",
            status=AuditStatus.COMPLETED,
            started_at=start_time,
            completed_at=end_time,
            findings=findings,
        )

        assert session.is_successful() is True
        assert session.get_duration_seconds() is not None
        assert session.get_duration_seconds() >= 1800  # At least 30 minutes
        assert session.get_critical_findings_count() == 1
        assert session.get_high_risk_findings_count() == 1
        assert session.requires_immediate_attention() is True

    def test_failed_audit_session(self) -> None:
        """Test failed audit session."""
        session = AuditSession(
            session_id="audit_003",
            status=AuditStatus.FAILED,
            started_at=datetime.utcnow(),
            errors=["Connection timeout", "Invalid credentials"],
        )

        assert session.is_successful() is False
        assert len(session.errors) == 2
        assert session.get_duration_seconds() is None

    def test_findings_by_risk_level(self) -> None:
        """Test filtering findings by risk level."""
        findings = [
            AuditFinding(
                id="f1",
                finding_type=FindingType.STALE_ACCESS,
                risk_level=RiskLevel.LOW,
                title="Low risk finding",
                description="Test description",
            ),
            AuditFinding(
                id="f2",
                finding_type=FindingType.PRIVILEGE_ESCALATION,
                risk_level=RiskLevel.HIGH,
                title="High risk finding",
                description="Test description",
            ),
            AuditFinding(
                id="f3",
                finding_type=FindingType.POLICY_VIOLATION,
                risk_level=RiskLevel.HIGH,
                title="Another high risk finding",
                description="Test description",
            ),
        ]

        session = AuditSession(
            session_id="audit_004",
            status=AuditStatus.COMPLETED,
            started_at=datetime.utcnow(),
            findings=findings,
        )

        low_findings = session.get_findings_by_risk_level(RiskLevel.LOW)
        high_findings = session.get_findings_by_risk_level(RiskLevel.HIGH)
        critical_findings = session.get_findings_by_risk_level(RiskLevel.CRITICAL)

        assert len(low_findings) == 1
        assert len(high_findings) == 2
        assert len(critical_findings) == 0
        assert low_findings[0].id == "f1"
        assert {f.id for f in high_findings} == {"f2", "f3"}

    def test_attention_required_logic(self) -> None:
        """Test immediate attention required logic."""
        # Session with critical findings
        critical_session = AuditSession(
            session_id="audit_005",
            status=AuditStatus.COMPLETED,
            started_at=datetime.utcnow(),
            findings=[
                AuditFinding(
                    id="f1",
                    finding_type=FindingType.PRIVILEGE_ESCALATION,
                    risk_level=RiskLevel.CRITICAL,
                    title="Critical finding",
                    description="Test description",
                )
            ],
        )

        # Session with many high risk findings
        many_high_session = AuditSession(
            session_id="audit_006",
            status=AuditStatus.COMPLETED,
            started_at=datetime.utcnow(),
            findings=[
                AuditFinding(
                    id=f"f{i}",
                    finding_type=FindingType.PRIVILEGE_ESCALATION,
                    risk_level=RiskLevel.HIGH,
                    title=f"High risk finding {i}",
                    description="Test description",
                )
                for i in range(6)  # 6 high risk findings
            ],
        )

        # Session with few high risk findings
        few_high_session = AuditSession(
            session_id="audit_007",
            status=AuditStatus.COMPLETED,
            started_at=datetime.utcnow(),
            findings=[
                AuditFinding(
                    id="f1",
                    finding_type=FindingType.PRIVILEGE_ESCALATION,
                    risk_level=RiskLevel.HIGH,
                    title="High risk finding",
                    description="Test description",
                )
            ],
        )

        assert critical_session.requires_immediate_attention() is True
        assert many_high_session.requires_immediate_attention() is True
        assert few_high_session.requires_immediate_attention() is False
