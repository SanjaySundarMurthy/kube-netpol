"""Terminal reporter — rich terminal output for kube-netpol."""
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule

from kube_netpol.models import (
    AnalysisReport, Severity, TrafficVerdict,
    SEVERITY_COLORS, SEVERITY_ICONS, VERDICT_COLORS, VERDICT_ICONS,
)


GRADE_COLORS = {
    "A+": "bright_green", "A": "green", "A-": "green",
    "B+": "bright_yellow", "B": "yellow", "B-": "yellow",
    "C+": "dark_orange", "C": "dark_orange", "C-": "dark_orange",
    "D": "red", "D-": "red",
    "F": "bright_red",
}

BANNER = r"""[bright_cyan]
  _          _                          _               _
 | | ___   _| |__   ___       _ __   ___| |_ _ __   ___ | |
 | |/ / | | | '_ \ / _ \     | '_ \ / _ \ __| '_ \ / _ \| |
 |   <| |_| | |_) |  __/  _  | | | |  __/ |_| |_) | (_) | |
 |_|\_\\__,_|_.__/ \___| (_) |_| |_|\___|\__| .__/ \___/|_|
                                             |_|
[/bright_cyan]
[dim]  Kubernetes NetworkPolicy Generator, Validator & Visualizer[/dim]
[dim]  v1.0.0 — 50+ validation rules | 10 policy templates | Traffic simulator[/dim]
"""


def print_report(report: AnalysisReport, console: Console, verbose: bool = False):
    """Print the full analysis report."""
    console.print(BANNER)
    console.print()

    _print_overview(report, console)
    console.print()

    _print_score(report, console)
    console.print()

    _print_severity_summary(report, console)
    console.print()

    _print_policy_summary(report, console)
    console.print()

    if report.issues:
        _print_issues(report, console, verbose)
        console.print()

    if report.connections:
        _print_traffic_map(report, console)
        console.print()

    if report.traffic_flows:
        _print_simulation_results(report, console)
        console.print()

    _print_recommendations(report, console)
    console.print()

    _print_footer(report, console)


def _print_overview(report: AnalysisReport, console: Console):
    """Print scan overview."""
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column()

    info.add_row("Scan Path:", report.scan_path)
    info.add_row("Policies Found:", str(report.total_policies))

    namespaces = set(p.namespace for p in report.policies)
    info.add_row("Namespaces:", ", ".join(sorted(namespaces)) if namespaces else "none")

    panel = Panel(info, title="🌐 Scan Overview", border_style="cyan", padding=(1, 2))
    console.print(panel)


def _print_score(report: AnalysisReport, console: Console):
    """Print security score."""
    grade_color = GRADE_COLORS.get(report.grade, "white")

    score_text = Text()
    score_text.append("  Security Score: ", style="bold")
    score_text.append(f"{report.score}", style=f"bold {grade_color}")
    score_text.append(f" / 100", style="dim")
    score_text.append("    Grade: ", style="bold")
    score_text.append(f" {report.grade} ", style=f"bold white on {grade_color}")

    bar_width = 40
    filled = int(report.score / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    bar_text = Text()
    bar_text.append("  [", style="dim")
    bar_text.append(bar[:filled], style=grade_color)
    bar_text.append(bar[filled:], style="dim")
    bar_text.append("]", style="dim")

    panel_content = Text()
    panel_content.append_text(score_text)
    panel_content.append("\n")
    panel_content.append_text(bar_text)

    panel = Panel(panel_content, title="🛡️ Network Security Score", border_style=grade_color, padding=(1, 2))
    console.print(panel)


def _print_severity_summary(report: AnalysisReport, console: Console):
    """Print severity breakdown."""
    table = Table(title="Issues by Severity", box=None, padding=(0, 3), show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Bar", min_width=30)

    severity_counts = {
        Severity.CRITICAL: report.critical_count,
        Severity.HIGH: report.high_count,
        Severity.MEDIUM: report.medium_count,
        Severity.LOW: report.low_count,
        Severity.INFO: report.info_count,
    }

    max_count = max(severity_counts.values()) if any(severity_counts.values()) else 1

    for sev, count in severity_counts.items():
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        bar_len = int(count / max(max_count, 1) * 25) if count > 0 else 0
        bar = "█" * bar_len

        table.add_row(
            f"{icon} {sev.value.upper()}",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{bar}[/{color}]",
        )

    console.print(table)


def _print_policy_summary(report: AnalysisReport, console: Console):
    """Print per-policy summary."""
    if not report.policies:
        return

    table = Table(title="📋 Policies Analyzed", box=None, padding=(0, 2), show_header=True)
    table.add_column("Policy", style="bold cyan")
    table.add_column("Namespace", style="dim")
    table.add_column("Types")
    table.add_column("Ingress Rules", justify="center")
    table.add_column("Egress Rules", justify="center")
    table.add_column("Target")

    for pol in report.policies:
        types_str = ", ".join(pol.policy_types) if pol.policy_types else "[dim]implicit[/dim]"

        selector = pol.pod_selector
        if isinstance(selector, dict) and selector.get("matchLabels"):
            target = ", ".join(f"{k}={v}" for k, v in selector["matchLabels"].items())
        else:
            target = "[yellow]All pods[/yellow]"

        table.add_row(
            pol.name,
            pol.namespace,
            types_str,
            str(len(pol.ingress_rules)),
            str(len(pol.egress_rules)),
            target,
        )

    console.print(table)


def _print_issues(report: AnalysisReport, console: Console, verbose: bool):
    """Print issues table."""
    severity_order = list(Severity)
    sorted_issues = sorted(report.issues, key=lambda i: severity_order.index(i.severity))

    table = Table(
        title=f"🔍 Issues Found ({len(report.issues)})",
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Rule", style="bold cyan", width=10)
    table.add_column("Sev", width=5, justify="center")
    table.add_column("Policy", width=25)
    table.add_column("Message", min_width=45)

    if verbose:
        table.add_column("Suggestion", style="italic green", min_width=30)

    max_display = 40 if not verbose else len(sorted_issues)

    for issue in sorted_issues[:max_display]:
        sev_color = SEVERITY_COLORS[issue.severity]
        sev_icon = SEVERITY_ICONS[issue.severity]

        row = [
            issue.rule_id,
            f"[{sev_color}]{sev_icon}[/{sev_color}]",
            issue.policy_name or issue.file_path,
            f"[{sev_color}]{issue.message}[/{sev_color}]",
        ]

        if verbose and issue.suggestion:
            row.append(issue.suggestion)

        table.add_row(*row)

    if len(sorted_issues) > max_display:
        console.print(f"\n  [dim]... and {len(sorted_issues) - max_display} more issues. Use --verbose to see all.[/dim]")

    console.print(table)


def _print_traffic_map(report: AnalysisReport, console: Console):
    """Print ASCII traffic map."""
    from kube_netpol.reporters.visualizer import generate_ascii_map
    map_text = generate_ascii_map(report.policies, [])
    if map_text.strip():
        panel = Panel(map_text, title="🗺️ Traffic Map", border_style="blue", padding=(1, 2))
        console.print(panel)


def _print_simulation_results(report: AnalysisReport, console: Console):
    """Print traffic simulation results."""
    table = Table(title="🧪 Traffic Simulation Results", show_lines=True, padding=(0, 1))
    table.add_column("Source", style="cyan")
    table.add_column("→", width=2, justify="center")
    table.add_column("Destination", style="cyan")
    table.add_column("Port")
    table.add_column("Verdict", justify="center")
    table.add_column("Reason", style="dim")

    for flow in report.traffic_flows:
        v_icon = VERDICT_ICONS[flow.verdict]
        v_color = VERDICT_COLORS[flow.verdict]

        port_str = f"{flow.port}/{flow.protocol}" if flow.port else "any"

        table.add_row(
            f"{flow.source_pod}\n(ns:{flow.source_namespace})",
            "→",
            f"{flow.dest_pod}\n(ns:{flow.dest_namespace})",
            port_str,
            f"[{v_color}]{v_icon} {flow.verdict.value}[/{v_color}]",
            flow.matched_rule[:60] if flow.matched_rule else "",
        )

    console.print(table)


def _print_recommendations(report: AnalysisReport, console: Console):
    """Print top recommendations."""
    if not report.issues:
        console.print(Panel(
            "[bright_green]✨ All network policies look great! Zero-trust networking achieved.[/bright_green]",
            title="🎉 Perfect Score",
            border_style="bright_green",
        ))
        return

    priority = [i for i in report.issues if i.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not priority:
        priority = [i for i in report.issues if i.severity == Severity.MEDIUM]

    recs = []
    seen = set()
    for issue in priority[:5]:
        if issue.suggestion and issue.suggestion not in seen:
            seen.add(issue.suggestion)
            sev_icon = SEVERITY_ICONS[issue.severity]
            sev_color = SEVERITY_COLORS[issue.severity]
            recs.append(f"  [{sev_color}]{sev_icon} [{issue.rule_id}][/{sev_color}] {issue.suggestion}")

    if recs:
        console.print(Panel(
            "\n".join(recs),
            title="💡 Top Recommendations",
            border_style="yellow",
            padding=(1, 2),
        ))


def _print_footer(report: AnalysisReport, console: Console):
    """Print footer."""
    console.print(Rule(style="dim"))
    total = len(report.issues)
    if total == 0:
        console.print("[bright_green]  ✅ Network policies are solid! Zero-trust networking achieved.[/bright_green]")
    elif report.critical_count > 0:
        console.print(f"[bright_red]  ⛔ {report.critical_count} critical network security issue(s) found.[/bright_red]")
    elif report.high_count > 0:
        console.print(f"[red]  ⚠️  {report.high_count} high-severity issue(s) should be addressed.[/red]")
    else:
        console.print(f"[yellow]  💡 {total} suggestion(s) to improve network security.[/yellow]")

    console.print(f"[dim]  kube-netpol v1.0.0 | 50+ rules | 10 templates | Made with ❤️  for K8s security[/dim]")
    console.print()
