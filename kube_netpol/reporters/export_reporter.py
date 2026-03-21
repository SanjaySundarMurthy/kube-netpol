"""JSON & HTML export reporters for kube-netpol."""
import json
from datetime import datetime, timezone

from kube_netpol.models import AnalysisReport, Severity, TrafficVerdict


def _traffic_sim_section(flows_rows: str) -> str:
    """Build traffic simulation section if flows exist."""
    if not flows_rows:
        return ""
    return (
        "<h2>🧪 Traffic Simulation</h2><div class='card'><table>"
        "<thead><tr><th>Source</th><th></th><th>Destination</th><th>Port</th><th>Verdict</th><th>Reason</th></tr></thead>"
        f"<tbody>{flows_rows}</tbody></table></div>"
    )

def export_json(report: AnalysisReport, output_path: str):
    """Export report as JSON."""
    data = {
        "tool": "kube-netpol",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_path": report.scan_path,
        "score": report.score,
        "grade": report.grade,
        "summary": {
            "total_policies": report.total_policies,
            "issues_by_severity": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
        },
        "policies": [
            {
                "name": p.name,
                "namespace": p.namespace,
                "policy_types": p.policy_types,
                "pod_selector": p.pod_selector,
                "ingress_rules_count": len(p.ingress_rules),
                "egress_rules_count": len(p.egress_rules),
            }
            for p in report.policies
        ],
        "issues": [
            {
                "rule_id": i.rule_id,
                "severity": i.severity.value,
                "message": i.message,
                "policy_name": i.policy_name,
                "file": i.file_path,
                "suggestion": i.suggestion,
                "doc_url": i.doc_url,
            }
            for i in report.issues
        ],
        "traffic_flows": [
            {
                "source": f"{f.source_pod}@{f.source_namespace}",
                "destination": f"{f.dest_pod}@{f.dest_namespace}",
                "port": f.port,
                "protocol": f.protocol,
                "verdict": f.verdict.value,
                "matched_rule": f.matched_rule,
            }
            for f in report.traffic_flows
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_html(report: AnalysisReport, output_path: str):
    """Export report as interactive HTML dashboard."""
    sev_colors = {
        "Critical": "#ef4444", "High": "#f97316",
        "Medium": "#eab308", "Low": "#06b6d4", "Info": "#9ca3af",
    }

    grade_color_map = {
        "A+": "#22c55e", "A": "#22c55e", "A-": "#4ade80",
        "B+": "#facc15", "B": "#eab308", "B-": "#ca8a04",
        "C+": "#f97316", "C": "#ea580c", "C-": "#dc2626",
        "D": "#dc2626", "D-": "#b91c1c", "F": "#7f1d1d",
    }
    grade_color = grade_color_map.get(report.grade, "#6b7280")

    severity_data = {
        "Critical": report.critical_count, "High": report.high_count,
        "Medium": report.medium_count, "Low": report.low_count, "Info": report.info_count,
    }

    # Build mermaid diagram
    from kube_netpol.reporters.visualizer import generate_mermaid
    mermaid_code = generate_mermaid(report.policies, [])

    issues_rows = ""
    for issue in sorted(report.issues, key=lambda x: list(Severity).index(x.severity)):
        sc = sev_colors.get(issue.severity.value.capitalize(), "#9ca3af")
        suggestion = f'<div class="suggestion">{issue.suggestion}</div>' if issue.suggestion else ""
        issues_rows += f"""
        <tr>
            <td><code>{issue.rule_id}</code></td>
            <td><span class="badge" style="background:{sc}">{issue.severity.value.upper()}</span></td>
            <td>{issue.policy_name or '-'}</td>
            <td>{issue.message}{suggestion}</td>
        </tr>"""

    policies_rows = ""
    for pol in report.policies:
        sel = pol.pod_selector
        if isinstance(sel, dict) and sel.get("matchLabels"):
            target = ", ".join(f"{k}={v}" for k, v in sel["matchLabels"].items())
        else:
            target = "All pods"
        types = ", ".join(pol.policy_types) if pol.policy_types else "implicit"
        policies_rows += f"""
        <tr>
            <td><strong>{pol.name}</strong></td>
            <td>{pol.namespace}</td>
            <td>{types}</td>
            <td>{len(pol.ingress_rules)}</td>
            <td>{len(pol.egress_rules)}</td>
            <td><code>{target}</code></td>
        </tr>"""

    flows_rows = ""
    for fl in report.traffic_flows:
        v_color = "#22c55e" if fl.verdict == TrafficVerdict.ALLOW else "#ef4444" if fl.verdict == TrafficVerdict.DENY else "#eab308"
        v_text = fl.verdict.value
        port_str = f"{fl.port}/{fl.protocol}" if fl.port else "any"
        flows_rows += f"""
        <tr>
            <td>{fl.source_pod}<br><small>ns:{fl.source_namespace}</small></td>
            <td>→</td>
            <td>{fl.dest_pod}<br><small>ns:{fl.dest_namespace}</small></td>
            <td>{port_str}</td>
            <td><span class="badge" style="background:{v_color}">{v_text}</span></td>
            <td><small>{fl.matched_rule[:80] if fl.matched_rule else ''}</small></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>kube-netpol Report</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; color: #38bdf8; }}
        h2 {{ font-size: 1.25rem; color: #94a3b8; margin: 1.5rem 0 0.75rem; }}
        .subtitle {{ color: #94a3b8; margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 1.25rem; border: 1px solid #334155; }}
        .card h3 {{ color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; margin-bottom: 0.5rem; }}
        .score {{ font-size: 2.5rem; font-weight: bold; }}
        .grade {{ display: inline-block; padding: 0.2rem 0.8rem; border-radius: 8px; font-size: 1.25rem; font-weight: bold; background: {grade_color}; color: white; }}
        .stat {{ font-size: 1.75rem; font-weight: bold; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
        th {{ text-align: left; padding: 0.6rem; background: #1e293b; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; border-bottom: 2px solid #334155; }}
        td {{ padding: 0.6rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
        tr:hover {{ background: #1e293b; }}
        .badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 4px; color: white; font-size: 0.7rem; font-weight: bold; }}
        code {{ background: #334155; padding: 0.1rem 0.3rem; border-radius: 4px; font-size: 0.8rem; }}
        .suggestion {{ color: #4ade80; font-size: 0.8rem; margin-top: 0.2rem; font-style: italic; }}
        .severity-bar {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.75rem 0; }}
        .sev-item {{ text-align: center; }}
        .sev-count {{ font-size: 1.25rem; font-weight: bold; }}
        .sev-label {{ font-size: 0.7rem; color: #94a3b8; }}
        .progress-bar {{ width: 100%; height: 6px; background: #334155; border-radius: 4px; overflow: hidden; margin-top: 0.4rem; }}
        .progress-fill {{ height: 100%; border-radius: 4px; }}
        .mermaid {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; margin: 1rem 0; }}
        .footer {{ text-align: center; color: #475569; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #1e293b; }}
        .tabs {{ display: flex; gap: 0.5rem; margin: 1rem 0; }}
        .tab {{ padding: 0.4rem 0.8rem; border: 1px solid #334155; background: #1e293b; color: #e2e8f0; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }}
        .tab:hover, .tab.active {{ background: #38bdf8; color: #0f172a; border-color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 kube-netpol Report</h1>
        <p class="subtitle">Network Policy Analysis &mdash; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>

        <div class="grid">
            <div class="card">
                <h3>Security Score</h3>
                <span class="score" style="color: {grade_color}">{report.score}</span><span style="color:#64748b">/100</span>
                <div class="progress-bar"><div class="progress-fill" style="width:{report.score}%; background:{grade_color}"></div></div>
            </div>
            <div class="card"><h3>Grade</h3><span class="grade">{report.grade}</span></div>
            <div class="card"><h3>Policies</h3><span class="stat">{report.total_policies}</span></div>
            <div class="card"><h3>Issues</h3><span class="stat">{len(report.issues)}</span></div>
        </div>

        <div class="card">
            <h3>Issues by Severity</h3>
            <div class="severity-bar">
                {"".join(f'<div class="sev-item"><div class="sev-count" style="color:{sev_colors[k]}">{v}</div><div class="sev-label">{k}</div></div>' for k, v in severity_data.items())}
            </div>
        </div>

        <h2>📋 Policies</h2>
        <div class="card">
            <table>
                <thead><tr><th>Name</th><th>Namespace</th><th>Types</th><th>Ingress</th><th>Egress</th><th>Target</th></tr></thead>
                <tbody>{policies_rows}</tbody>
            </table>
        </div>

        <h2>🗺️ Traffic Flow Diagram</h2>
        <div class="mermaid">
{mermaid_code}
        </div>

        <h2>🔍 Issues ({len(report.issues)})</h2>
        <div class="card">
            <table>
                <thead><tr><th>Rule</th><th>Severity</th><th>Policy</th><th>Message</th></tr></thead>
                <tbody>{issues_rows}</tbody>
            </table>
        </div>

        {_traffic_sim_section(flows_rows)}

        <div class="footer">
            kube-netpol v1.0.0 &bull; 34+ rules &bull; 10 templates &bull; Made with ❤️ for K8s security
        </div>
    </div>
    <script>mermaid.initialize({{startOnLoad:true, theme:'dark'}});</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
