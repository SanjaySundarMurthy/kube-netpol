"""Tests for kube-netpol data models."""
from kube_netpol.models import (
    Severity, PolicyType, TrafficVerdict,
    Issue, NetworkPolicy, TrafficFlow, PolicyConnection, AnalysisReport,
)


class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_policy_type_values(self):
        assert PolicyType.INGRESS.value == "Ingress"
        assert PolicyType.EGRESS.value == "Egress"
        assert PolicyType.BOTH.value == "Ingress+Egress"

    def test_traffic_verdict_values(self):
        assert TrafficVerdict.ALLOW.value == "ALLOW"
        assert TrafficVerdict.DENY.value == "DENY"
        assert TrafficVerdict.UNKNOWN.value == "UNKNOWN"


class TestIssue:
    def test_create_issue(self):
        issue = Issue(
            rule_id="KNP-001",
            severity=Severity.HIGH,
            message="Test issue",
            file_path="test.yaml",
        )
        assert issue.rule_id == "KNP-001"
        assert issue.severity == Severity.HIGH
        assert issue.policy_name == ""

    def test_issue_with_all_fields(self):
        issue = Issue(
            rule_id="KNP-010",
            severity=Severity.MEDIUM,
            message="Port issue",
            file_path="test.yaml",
            policy_name="my-policy",
            line=10,
            suggestion="Add port restrictions",
        )
        assert issue.policy_name == "my-policy"
        assert issue.line == 10


class TestNetworkPolicy:
    def test_default_values(self):
        pol = NetworkPolicy(name="test")
        assert pol.namespace == "default"
        assert pol.pod_selector == {}
        assert pol.policy_types == []
        assert pol.ingress_rules == []
        assert pol.egress_rules == []

    def test_with_rules(self):
        pol = NetworkPolicy(
            name="allow-web",
            namespace="production",
            policy_types=["Ingress"],
            ingress_rules=[{"from": [{"podSelector": {"matchLabels": {"app": "frontend"}}}]}],
        )
        assert pol.namespace == "production"
        assert len(pol.ingress_rules) == 1


class TestTrafficFlow:
    def test_default_verdict(self):
        flow = TrafficFlow(
            source_pod="web",
            source_namespace="default",
            source_labels={},
            dest_pod="api",
            dest_namespace="default",
            dest_labels={},
        )
        assert flow.verdict == TrafficVerdict.UNKNOWN
        assert flow.protocol == "TCP"


class TestAnalysisReport:
    def test_empty_report(self):
        report = AnalysisReport(scan_path="/tmp/test")
        assert report.score == 100.0
        assert report.grade == "A+"
        assert report.critical_count == 0

    def test_severity_counts(self):
        issues = [
            Issue("KNP-001", Severity.CRITICAL, "crit", "f.yaml"),
            Issue("KNP-002", Severity.HIGH, "high", "f.yaml"),
            Issue("KNP-003", Severity.HIGH, "high2", "f.yaml"),
            Issue("KNP-004", Severity.MEDIUM, "med", "f.yaml"),
        ]
        report = AnalysisReport(scan_path="/tmp", issues=issues)
        assert report.critical_count == 1
        assert report.high_count == 2
        assert report.medium_count == 1

    def test_calculate_score(self):
        issues = [
            Issue("KNP-001", Severity.CRITICAL, "crit", "f.yaml"),
            Issue("KNP-002", Severity.CRITICAL, "crit2", "f.yaml"),
        ]
        report = AnalysisReport(scan_path="/tmp", total_policies=3, issues=issues)
        report.calculate_score()
        assert report.score < 100
        assert report.grade != "A+"

    def test_perfect_score_no_issues(self):
        report = AnalysisReport(scan_path="/tmp", total_policies=5)
        report.calculate_score()
        assert report.score == 100.0
        assert report.grade == "A+"
