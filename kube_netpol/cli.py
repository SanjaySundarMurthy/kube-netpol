"""kube-netpol CLI — Kubernetes NetworkPolicy generator, validator & visualizer."""
import os
import sys

import click
from rich.console import Console

from kube_netpol import __version__
from kube_netpol.analyzers.simulator import simulate_traffic
from kube_netpol.analyzers.validator import validate_policies
from kube_netpol.generators.policy_generator import TEMPLATES, generate_policy, list_templates
from kube_netpol.models import AnalysisReport, Severity, TrafficFlow
from kube_netpol.parser import parse_manifests
from kube_netpol.reporters.export_reporter import export_html, export_json
from kube_netpol.reporters.terminal_reporter import print_report
from kube_netpol.reporters.visualizer import build_connections

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="kube-netpol")
def main():
    """kube-netpol — Kubernetes NetworkPolicy generator, validator & visualizer.

    Validate existing NetworkPolicies, generate secure templates,
    simulate traffic flows, and visualize network connectivity.
    """
    pass


# ─── scan ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show suggestions and full details")
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "json", "html"]), default="terminal")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output file path for JSON/HTML export")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), help="Exit with code 1 if issues of this severity or above are found")
@click.option("--simulate", "-s", is_flag=True, help="Run traffic simulation with common flows")
def scan(path, verbose, output_format, output_path, fail_on, simulate):
    """Scan and validate Kubernetes NetworkPolicies.

    PATH is a YAML file or directory containing Kubernetes manifests.
    """
    abs_path = os.path.abspath(path)

    # Parse
    policies, workloads = parse_manifests(abs_path)

    # Validate
    issues = validate_policies(policies, workloads)

    # Build report
    report = AnalysisReport(
        scan_path=abs_path,
        total_policies=len(policies),
        policies=policies,
        issues=issues,
    )

    # Build connections for visualization
    report.connections = build_connections(policies, workloads)

    # Optional simulation
    if simulate:
        flows = _generate_common_flows(policies, workloads)
        report.traffic_flows = simulate_traffic(policies, flows)

    # Calculate score
    report.calculate_score()

    # Output
    if output_format == "json":
        dest = output_path or "kube-netpol-report.json"
        export_json(report, dest)
        console.print(f"[green]JSON report saved to {dest}[/green]")
    elif output_format == "html":
        dest = output_path or "kube-netpol-report.html"
        export_html(report, dest)
        console.print(f"[green]HTML report saved to {dest}[/green]")
    else:
        print_report(report, console, verbose)

    # CI/CD fail gate
    if fail_on:
        severity_levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        threshold_idx = severity_levels.index(Severity(fail_on))
        triggered = [s for s in severity_levels[:threshold_idx + 1]]
        if any(i.severity in triggered for i in issues):
            raise SystemExit(1)


# ─── generate ───────────────────────────────────────────────────────────────

@main.command()
@click.argument("template", type=click.Choice(list(TEMPLATES.keys())))
@click.option("--namespace", "-n", default="default", show_default=True, help="Target namespace")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Write YAML to file instead of stdout")
@click.option("--app", default=None, help="Application name (for web-app, backend-api, database, microservices-suite templates)")
def generate(template, namespace, output_path, app):
    """Generate a NetworkPolicy from a built-in template.

    TEMPLATE is the name of the policy template to use.
    """
    kwargs = {}
    if app:
        kwargs["app"] = app

    yaml_output = generate_policy(template, namespace, **kwargs)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(yaml_output)
        console.print(f"[green]Policy written to {output_path}[/green]")
    else:
        console.print(f"\n[bold cyan]# Template: {template} | Namespace: {namespace}[/bold cyan]\n")
        console.print(yaml_output)


# ─── simulate ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--from-pod", "source_pod", required=True, help="Source pod name")
@click.option("--from-ns", "source_ns", default="default", help="Source namespace")
@click.option("--from-labels", "source_labels", default="", help="Source labels (k=v,k=v)")
@click.option("--to-pod", "dest_pod", required=True, help="Destination pod name")
@click.option("--to-ns", "dest_ns", default="default", help="Destination namespace")
@click.option("--to-labels", "dest_labels", default="", help="Destination labels (k=v,k=v)")
@click.option("--port", "-p", type=int, default=None, help="Destination port")
@click.option("--protocol", default="TCP", type=click.Choice(["TCP", "UDP", "SCTP"]))
def simulate(path, source_pod, source_ns, source_labels, dest_pod, dest_ns, dest_labels, port, protocol):
    """Simulate a single traffic flow against existing policies.

    PATH is a YAML file or directory containing NetworkPolicies.
    """
    abs_path = os.path.abspath(path)
    policies, _ = parse_manifests(abs_path)

    if not policies:
        console.print("[red]No NetworkPolicies found — all traffic is unrestricted.[/red]")
        return

    src_lbl = _parse_labels(source_labels)
    dst_lbl = _parse_labels(dest_labels)

    flow = TrafficFlow(
        source_pod=source_pod,
        source_namespace=source_ns,
        source_labels=src_lbl,
        dest_pod=dest_pod,
        dest_namespace=dest_ns,
        dest_labels=dst_lbl,
        port=port,
        protocol=protocol,
    )

    results = simulate_traffic(policies, [flow])
    result = results[0]

    from kube_netpol.models import VERDICT_COLORS, VERDICT_ICONS
    icon = VERDICT_ICONS[result.verdict]
    color = VERDICT_COLORS[result.verdict]

    console.print()
    console.print("  [bold]Traffic Flow:[/bold]")
    console.print(f"    Source: [cyan]{source_pod}[/cyan] (ns:{source_ns}) labels={src_lbl}")
    console.print(f"    Dest:   [cyan]{dest_pod}[/cyan] (ns:{dest_ns}) labels={dst_lbl}")
    console.print(f"    Port:   {port or 'any'}/{protocol}")
    console.print()
    console.print(f"  [bold]Verdict:[/bold] [{color}]{icon} {result.verdict.value}[/{color}]")
    if result.matched_rule:
        console.print(f"  [dim]Reason: {result.matched_rule}[/dim]")
    console.print()


# ─── templates ──────────────────────────────────────────────────────────────

@main.command()
def templates():
    """List all available policy templates."""
    from rich.table import Table

    table = Table(title="📋 Available Policy Templates", show_lines=True, padding=(0, 1))
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Template Name", style="bold cyan", min_width=25)
    table.add_column("Display Name", style="bold")
    table.add_column("Description", min_width=40)

    for idx, tmpl in enumerate(list_templates(), 1):
        table.add_row(str(idx), tmpl["name"], tmpl["display_name"], tmpl["description"])

    console.print()
    console.print(table)
    console.print("\n[dim]  Usage: kube-netpol generate <template-name> --namespace <ns>[/dim]\n")


# ─── visualize ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", "vis_format", type=click.Choice(["mermaid", "ascii"]), default="ascii")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Save output to file")
def visualize(path, vis_format, output_path):
    """Visualize NetworkPolicy connections.

    PATH is a YAML file or directory containing Kubernetes manifests.
    """
    abs_path = os.path.abspath(path)
    policies, workloads = parse_manifests(abs_path)

    if not policies:
        console.print("[yellow]No NetworkPolicies found to visualize.[/yellow]")
        return

    if vis_format == "mermaid":
        from kube_netpol.reporters.visualizer import generate_mermaid
        output = generate_mermaid(policies, workloads)
    else:
        from kube_netpol.reporters.visualizer import generate_ascii_map
        output = generate_ascii_map(policies, workloads)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        console.print(f"[green]Visualization saved to {output_path}[/green]")
    else:
        console.print()
        console.print(output)
        console.print()


# ─── demo ───────────────────────────────────────────────────────────────────

@main.command()
@click.option("--verbose", "-v", is_flag=True, help="Show all details and suggestions")
def demo(verbose):
    """Run a demo scan with sample Kubernetes manifests.

    Creates a realistic e-commerce cluster with intentional
    NetworkPolicy issues to demonstrate all kube-netpol features.
    """
    from kube_netpol.demo import create_demo_manifests

    demo_dir = create_demo_manifests()
    console.print(f"[dim]  Demo manifests created in: {demo_dir}[/dim]\n")

    policies, workloads = parse_manifests(demo_dir)
    issues = validate_policies(policies, workloads)

    report = AnalysisReport(
        scan_path=demo_dir,
        total_policies=len(policies),
        policies=policies,
        issues=issues,
    )

    report.connections = build_connections(policies, workloads)

    # Generate common traffic flows for simulation
    flows = _generate_common_flows(policies, workloads)
    report.traffic_flows = simulate_traffic(policies, flows)

    report.calculate_score()

    print_report(report, console, verbose)


# ─── rules ──────────────────────────────────────────────────────────────────

@main.command()
def rules():
    """List all validation rules."""
    from rich.table import Table

    table = Table(title="📏 Validation Rules", show_lines=True, padding=(0, 1))
    table.add_column("Rule ID", style="bold cyan", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Description", min_width=50)

    rule_defs = [
        ("KNP-001", "HIGH", "No NetworkPolicies found"),
        ("KNP-002", "LOW", "Policy name doesn't follow naming convention"),
        ("KNP-003", "LOW", "Policy missing standard labels"),
        ("KNP-004", "MEDIUM", "Empty pod selector selects all pods"),
        ("KNP-005", "MEDIUM", "policyTypes not explicitly set"),
        ("KNP-006", "MEDIUM", "Policy has ingress rules but Ingress not in policyTypes"),
        ("KNP-007", "MEDIUM", "Policy has egress rules but Egress not in policyTypes"),
        ("KNP-008", "HIGH", "Ingress allows from all sources (no 'from' specified)"),
        ("KNP-009", "HIGH", "Ingress allows from all namespaces"),
        ("KNP-010", "MEDIUM", "Ingress rule has no port restrictions"),
        ("KNP-011", "MEDIUM", "Large port range in ingress rule"),
        ("KNP-012", "HIGH", "Dangerous port exposed via ingress"),
        ("KNP-013", "HIGH", "Egress allows to all destinations (no 'to' specified)"),
        ("KNP-014", "HIGH", "Egress allows to all namespaces"),
        ("KNP-015", "MEDIUM", "Egress rule has no port restrictions"),
        ("KNP-016", "MEDIUM", "Large port range in egress rule"),
        ("KNP-017", "HIGH", "Dangerous port in egress rule"),
        ("KNP-018", "CRITICAL", "Egress to 0.0.0.0/0 without blocking cloud metadata"),
        ("KNP-019", "HIGH", "Ingress from 0.0.0.0/0 — allows internet traffic"),
        ("KNP-020", "MEDIUM", "Invalid CIDR notation in ipBlock"),
        ("KNP-021", "LOW", "Overly specific CIDR (/32 for single host)"),
        ("KNP-022", "MEDIUM", "IP block except range not within CIDR"),
        ("KNP-023", "LOW", "Duplicate policies with same pod selector"),
        ("KNP-024", "MEDIUM", "Conflicting rules between policies"),
        ("KNP-025", "CRITICAL", "No default-deny ingress policy"),
        ("KNP-026", "HIGH", "No default-deny egress policy"),
        ("KNP-027", "HIGH", "Workload not covered by any NetworkPolicy"),
        ("KNP-028", "MEDIUM", "Workload only has ingress policy, no egress restriction"),
        ("KNP-029", "MEDIUM", "Namespace has mixed isolation levels"),
        ("KNP-030", "MEDIUM", "No DNS egress rule found for namespace"),
        ("KNP-031", "INFO", "Policy has no effect (empty rules match nothing)"),
        ("KNP-032", "LOW", "Pod selector uses only one label"),
        ("KNP-033", "INFO", "Annotation suggests managed by external tool"),
        ("KNP-034", "HIGH", "SSH port (22) exposed from 0.0.0.0/0"),
    ]

    from kube_netpol.models import SEVERITY_COLORS, SEVERITY_ICONS
    for rule_id, sev_str, desc in rule_defs:
        sev = Severity(sev_str.lower())
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        table.add_row(rule_id, f"[{color}]{icon} {sev_str}[/{color}]", desc)

    console.print()
    console.print(table)
    console.print(f"\n[dim]  {len(rule_defs)} validation rules across 6 categories[/dim]\n")


# ─── Helpers ────────────────────────────────────────────────────────────────

def _parse_labels(label_str: str) -> dict:
    """Parse 'k=v,k2=v2' into a dict."""
    if not label_str:
        return {}
    result = {}
    for pair in label_str.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _generate_common_flows(policies, workloads) -> list:
    """Generate common traffic flows for simulation based on discovered workloads."""
    flows = []

    # Get unique pods from workloads
    pods = [w for w in workloads if w["kind"] != "Service"]
    if not pods:
        # Create synthetic flows from policy selectors
        for pol in policies:
            ns = pol.namespace
            labels = pol.pod_selector.get("matchLabels", {})
            if labels:
                pod_name = list(labels.values())[0]
                pods.append({"name": pod_name, "namespace": ns, "labels": labels})

    # Test each pair of pods
    seen = set()
    for src in pods:
        for dst in pods:
            if src["name"] == dst["name"]:
                continue

            key = f"{src['name']}->{dst['name']}"
            if key in seen:
                continue
            seen.add(key)

            # Test common ports
            for port in [80, 443, 8080, 5432, 6379, 9090]:
                flows.append(TrafficFlow(
                    source_pod=src["name"],
                    source_namespace=src.get("namespace", "default"),
                    source_labels=src.get("labels", {}),
                    dest_pod=dst["name"],
                    dest_namespace=dst.get("namespace", "default"),
                    dest_labels=dst.get("labels", {}),
                    port=port,
                    protocol="TCP",
                ))

            if len(flows) > 100:
                return flows

    return flows


if __name__ == "__main__":
    main()
