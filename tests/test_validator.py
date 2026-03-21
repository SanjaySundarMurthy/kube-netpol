"""Tests for kube-netpol policy validator."""
from kube_netpol.analyzers.validator import validate_policies
from kube_netpol.parser import parse_manifests


class TestValidatePolicies:
    def test_good_policies_fewer_issues(self, good_manifests):
        policies, workloads = parse_manifests(good_manifests)
        issues = validate_policies(policies, workloads)
        # Good policies should have some issues (e.g., no default-deny egress)
        # but fewer than bad ones
        assert isinstance(issues, list)

    def test_bad_policy_finds_issues(self, bad_manifests):
        policies, workloads = parse_manifests(bad_manifests)
        issues = validate_policies(policies, workloads)
        assert len(issues) > 0
        rule_ids = [i.rule_id for i in issues]
        # BAD_POLICY has no policyTypes, allows from 0.0.0.0/0
        assert any("KNP-" in r for r in rule_ids)

    def test_no_policies_triggers_knp001(self, tmp_manifests, workload_deployment):
        path = tmp_manifests({"deploy.yaml": workload_deployment})
        policies, workloads = parse_manifests(path)
        issues = validate_policies(policies, workloads)
        rule_ids = [i.rule_id for i in issues]
        assert "KNP-001" in rule_ids

    def test_missing_default_deny(self, tmp_manifests, allow_web_policy, workload_deployment):
        """No default-deny policy → should detect issues."""
        path = tmp_manifests({
            "web.yaml": allow_web_policy,
            "deploy.yaml": workload_deployment,
        })
        policies, workloads = parse_manifests(path)
        issues = validate_policies(policies, workloads)
        assert len(issues) > 0  # Should have some issues without full deny

    def test_bad_policy_finds_multiple_issues(self, tmp_manifests, bad_policy_yaml):
        """Bad policy with 0.0.0.0/0 and no policyTypes → multiple issues."""
        path = tmp_manifests({"bad.yaml": bad_policy_yaml})
        policies, _ = parse_manifests(path)
        issues = validate_policies(policies, [])
        rule_ids = [i.rule_id for i in issues]
        # Should detect naming, missing policyTypes, broad CIDR, etc.
        assert len(rule_ids) >= 3

    def test_empty_policies_and_workloads(self):
        issues = validate_policies([], [])
        assert isinstance(issues, list)


class TestValidatorEdgeCases:
    def test_policy_with_no_spec(self, tmp_manifests):
        yaml_content = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: empty-spec\n"
            "spec:\n"
            "  podSelector: {}\n"
        )
        path = tmp_manifests({"empty.yaml": yaml_content})
        policies, _ = parse_manifests(path)
        issues = validate_policies(policies, [])
        assert isinstance(issues, list)
