"""Tests for kube-netpol policy generator."""
from kube_netpol.generators.policy_generator import TEMPLATES, generate_policy, list_templates


class TestGeneratePolicy:
    def test_generate_default_deny_ingress(self):
        yaml_out = generate_policy("default-deny-ingress", "production")
        assert "NetworkPolicy" in yaml_out
        assert "production" in yaml_out
        assert "Ingress" in yaml_out

    def test_generate_default_deny_egress(self):
        yaml_out = generate_policy("default-deny-egress", "default")
        assert "Egress" in yaml_out

    def test_generate_default_deny_all(self):
        yaml_out = generate_policy("default-deny-all", "staging")
        assert "staging" in yaml_out

    def test_generate_allow_dns(self):
        yaml_out = generate_policy("allow-dns", "default")
        assert "53" in yaml_out
        assert "DNS" in yaml_out or "dns" in yaml_out.lower()

    def test_generate_web_app_with_app_name(self):
        yaml_out = generate_policy("web-app", "default", app="myapp")
        assert "myapp" in yaml_out

    def test_generate_returns_valid_yaml(self):
        import yaml
        yaml_out = generate_policy("default-deny-ingress", "test-ns")
        doc = yaml.safe_load(yaml_out)
        assert doc["kind"] == "NetworkPolicy"
        assert doc["metadata"]["namespace"] == "test-ns"


class TestListTemplates:
    def test_list_templates_returns_list(self):
        templates = list_templates()
        assert isinstance(templates, list)
        assert len(templates) > 0

    def test_templates_have_required_fields(self):
        templates = list_templates()
        for t in templates:
            assert "name" in t
            assert "description" in t

    def test_all_templates_in_dict(self):
        assert len(TEMPLATES) >= 5
        assert "default-deny-ingress" in TEMPLATES
        assert "allow-dns" in TEMPLATES
