"""Tests for kube-netpol YAML parser."""
from kube_netpol.parser import parse_manifests


class TestParseManifests:
    def test_parse_network_policy(self, tmp_manifests, default_deny_policy):
        path = tmp_manifests({"deny.yaml": default_deny_policy})
        policies, workloads = parse_manifests(path)
        assert len(policies) == 1
        assert policies[0].name == "default-deny-ingress"
        assert policies[0].namespace == "default"

    def test_parse_workload(self, tmp_manifests, workload_deployment):
        path = tmp_manifests({"deploy.yaml": workload_deployment})
        policies, workloads = parse_manifests(path)
        assert len(policies) == 0
        assert len(workloads) == 1
        assert workloads[0]["kind"] == "Deployment"
        assert workloads[0]["name"] == "web"

    def test_parse_mixed(self, good_manifests):
        policies, workloads = parse_manifests(good_manifests)
        assert len(policies) >= 2
        assert len(workloads) >= 1

    def test_parse_empty_directory(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        policies, workloads = parse_manifests(str(empty_dir))
        assert policies == []
        assert workloads == []

    def test_parse_invalid_yaml(self, tmp_manifests):
        path = tmp_manifests({"bad.yaml": "{{invalid: yaml: content{{"})
        policies, workloads = parse_manifests(path)
        assert policies == []
        assert workloads == []

    def test_parse_single_file(self, tmp_path, allow_web_policy):
        f = tmp_path / "policy.yaml"
        f.write_text(allow_web_policy, encoding="utf-8")
        policies, workloads = parse_manifests(str(f))
        assert len(policies) == 1
        assert policies[0].name == "allow-web"

    def test_parse_multi_document_yaml(self, tmp_manifests, default_deny_policy, workload_deployment):
        multi_doc = default_deny_policy + "---\n" + workload_deployment
        path = tmp_manifests({"multi.yaml": multi_doc})
        policies, workloads = parse_manifests(path)
        assert len(policies) == 1
        assert len(workloads) == 1

    def test_policy_fields_parsed(self, tmp_manifests, allow_web_policy):
        path = tmp_manifests({"web.yaml": allow_web_policy})
        policies, _ = parse_manifests(path)
        pol = policies[0]
        assert pol.pod_selector == {"matchLabels": {"app": "web"}}
        assert "Ingress" in pol.policy_types
        assert len(pol.ingress_rules) == 1
