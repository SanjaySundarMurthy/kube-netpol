# kube-netpol

**Kubernetes NetworkPolicy Generator, Validator & Visualizer**

A comprehensive CLI tool that validates existing Kubernetes NetworkPolicies, generates secure policy templates, simulates traffic flows, and visualizes network connectivity — all from your terminal.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Rules](https://img.shields.io/badge/validation%20rules-34+-orange.svg)
![Templates](https://img.shields.io/badge/policy%20templates-10-purple.svg)

---

## Why kube-netpol?

Kubernetes NetworkPolicies are the firewall of your cluster — but they're notoriously easy to get wrong. One missing `policyTypes` field and your "deny all" policy does nothing. One empty `namespaceSelector: {}` and you've opened traffic from every namespace.

**kube-netpol** catches these mistakes before they hit production:

- **34+ validation rules** covering security, correctness, and best practices
- **10 policy templates** from default-deny to full microservices zero-trust
- **Traffic simulation engine** that evaluates flows against your policies
- **Mermaid + ASCII visualization** of network connectivity
- **CI/CD ready** with --fail-on threshold and JSON/HTML export

---

## Installation

```bash
pip install -e .
```

Or directly from the repository:

```bash
git clone https://github.com/SanjaySundarMurthy/kube-netpol.git
cd kube-netpol
pip install -e .
```

---

## Quick Start

### Demo Mode (No Cluster Needed)

```bash
kube-netpol demo
```

This creates a realistic e-commerce cluster with intentional security issues and runs a full analysis — perfect for seeing what kube-netpol can do.

### Scan Existing Policies

```bash
# Scan a single file
kube-netpol scan my-network-policy.yaml

# Scan a directory of manifests
kube-netpol scan ./k8s/

# Verbose mode with suggestions
kube-netpol scan ./k8s/ --verbose

# With traffic simulation
kube-netpol scan ./k8s/ --simulate
```

### Generate Policies from Templates

```bash
# List all templates
kube-netpol templates

# Generate a default-deny-all policy
kube-netpol generate default-deny-all --namespace production

# Generate a complete microservices suite
kube-netpol generate microservices-suite --namespace ecommerce --app myshop

# Save to file
kube-netpol generate database --namespace production -o db-policy.yaml
```

### Simulate Traffic Flows

```bash
kube-netpol simulate ./k8s/ \
  --from-pod frontend --from-ns ecommerce --from-labels "app=frontend" \
  --to-pod backend --to-ns ecommerce --to-labels "app=backend-api" \
  --port 8080
```

### Visualize Connections

```bash
# ASCII traffic map
kube-netpol visualize ./k8s/

# Mermaid diagram (paste into GitHub, Notion, etc.)
kube-netpol visualize ./k8s/ --format mermaid

# Save to file
kube-netpol visualize ./k8s/ --format mermaid -o diagram.md
```

---

## CI/CD Integration

Use `--fail-on` to fail your pipeline when issues exceed a threshold:

```bash
# Fail on critical or high severity
kube-netpol scan ./k8s/ --fail-on high

# Export JSON for further processing
kube-netpol scan ./k8s/ --format json -o report.json

# Export interactive HTML dashboard
kube-netpol scan ./k8s/ --format html -o report.html
```

### GitHub Actions Example

```yaml
- name: Validate NetworkPolicies
  run: |
    pip install kube-netpol
    kube-netpol scan ./k8s/network-policies/ --fail-on high
```

---

## Validation Rules

34+ rules organized into 6 categories:

| Category | Rules | What It Catches |
|---|---|---|
| **Structure** | KNP-001 to KNP-003 | Missing policies, naming, labels |
| **Pod Selectors** | KNP-004 to KNP-007 | Overly broad selectors, missing policyTypes |
| **Ingress** | KNP-008 to KNP-012 | Open ingress, dangerous ports, missing restrictions |
| **Egress** | KNP-013 to KNP-018 | Unrestricted egress, cloud metadata SSRF, wide CIDRs |
| **IP Blocks** | KNP-019 to KNP-022 | Invalid CIDRs, internet exposure, /32 overuse |
| **Cross-Policy** | KNP-023 to KNP-034 | Duplicates, coverage gaps, missing default-deny, DNS |

View all rules:

```bash
kube-netpol rules
```

---

## Policy Templates

| Template | Description |
|---|---|
| `default-deny-ingress` | Block all inbound traffic |
| `default-deny-egress` | Block all outbound traffic |
| `default-deny-all` | Zero-trust baseline (both directions) |
| `allow-dns` | Allow DNS resolution via kube-dns |
| `allow-internet-egress` | Allow outbound HTTPS (blocking cloud metadata) |
| `web-app` | HTTP/HTTPS ingress + DNS egress |
| `backend-api` | Frontend → API ingress + DB egress |
| `database` | API-only ingress + DNS egress |
| `monitoring` | Prometheus scraping from monitoring namespace |
| `microservices-suite` | Complete 3-tier zero-trust (5 policies) |

---

## Output Formats

### Terminal (Default)
Rich terminal output with colored severity, score gauge, traffic map, and recommendations.

### JSON
Machine-readable report for CI/CD pipelines and custom dashboards.

### HTML
Interactive dashboard with Mermaid connectivity diagrams, sortable tables, and severity filtering.

---

## Architecture

```
kube_netpol/
├── cli.py              # Click CLI entry point
├── models.py           # Core data models (Issue, NetworkPolicy, TrafficFlow)
├── parser.py           # YAML manifest parser
├── demo.py             # Demo scenario generator
├── analyzers/
│   ├── validator.py    # 34+ validation rules
│   └── simulator.py    # Traffic flow simulation engine
├── generators/
│   └── policy_generator.py  # 10 policy templates
└── reporters/
    ├── terminal_reporter.py  # Rich terminal output
    ├── export_reporter.py    # JSON + HTML export
    └── visualizer.py         # Mermaid + ASCII diagrams
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Sai Sandeep** — Built with ❤️ for Kubernetes network security.
