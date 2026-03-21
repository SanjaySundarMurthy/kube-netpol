"""Shared test fixtures for kube-netpol."""
import pytest


@pytest.fixture
def tmp_manifests(tmp_path):
    """Factory fixture: creates temp directory with YAML manifests."""
    def _make(yamls: dict):
        manifest_dir = tmp_path / "manifests"
        manifest_dir.mkdir(exist_ok=True)
        for name, content in yamls.items():
            (manifest_dir / name).write_text(content, encoding="utf-8")
        return str(manifest_dir)
    return _make


@pytest.fixture
def default_deny_policy():
    return (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: default-deny-ingress\n"
        "  namespace: default\n"
        "spec:\n"
        "  podSelector: {}\n"
        "  policyTypes:\n"
        "    - Ingress\n"
    )


@pytest.fixture
def allow_web_policy():
    return (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: allow-web\n"
        "  namespace: default\n"
        "  labels:\n"
        "    app.kubernetes.io/name: allow-web\n"
        "spec:\n"
        "  podSelector:\n"
        "    matchLabels:\n"
        "      app: web\n"
        "  policyTypes:\n"
        "    - Ingress\n"
        "  ingress:\n"
        "    - from:\n"
        "        - podSelector:\n"
        "            matchLabels:\n"
        "              app: frontend\n"
        "      ports:\n"
        "        - protocol: TCP\n"
        "          port: 80\n"
    )


@pytest.fixture
def workload_deployment():
    return (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "  namespace: default\n"
        "spec:\n"
        "  template:\n"
        "    metadata:\n"
        "      labels:\n"
        "        app: web\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: nginx\n"
        "          image: nginx:1.25\n"
    )


@pytest.fixture
def bad_policy_yaml():
    """Policy with many issues: no policyTypes, allows from all, wide IP block."""
    return (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: BAD_POLICY\n"
        "  namespace: default\n"
        "spec:\n"
        "  podSelector:\n"
        "    matchLabels:\n"
        "      app: backend\n"
        "  ingress:\n"
        "    - from:\n"
        "        - ipBlock:\n"
        "            cidr: 0.0.0.0/0\n"
        "  egress:\n"
        "    - to:\n"
        "        - ipBlock:\n"
        "            cidr: 0.0.0.0/0\n"
    )


@pytest.fixture
def good_manifests(tmp_manifests, default_deny_policy, allow_web_policy, workload_deployment):
    return tmp_manifests({
        "deny.yaml": default_deny_policy,
        "web-policy.yaml": allow_web_policy,
        "deployment.yaml": workload_deployment,
    })


@pytest.fixture
def bad_manifests(tmp_manifests, bad_policy_yaml, workload_deployment):
    return tmp_manifests({
        "bad-policy.yaml": bad_policy_yaml,
        "deployment.yaml": workload_deployment,
    })
