"""Visualizer — generates Mermaid diagrams and connection maps for NetworkPolicies."""
from collections import defaultdict

from kube_netpol.models import PolicyConnection


def build_connections(policies: list, workloads: list) -> list:
    """Build a list of traffic connections from policies for visualization."""
    connections = []

    for pol in policies:
        selector_desc = _describe_selector(pol.pod_selector, pol.namespace)

        # Ingress connections
        for rule in pol.ingress_rules:
            from_peers = rule.get("from", [])
            ports = rule.get("ports", [])

            for peer in from_peers:
                source = _describe_peer(peer, pol.namespace, "source")
                connections.append(PolicyConnection(
                    source=source,
                    destination=selector_desc,
                    ports=ports,
                    direction="ingress",
                    policy_name=pol.name,
                ))

        # Egress connections
        for rule in pol.egress_rules:
            to_peers = rule.get("to", [])
            ports = rule.get("ports", [])

            for peer in to_peers:
                dest = _describe_peer(peer, pol.namespace, "dest")
                connections.append(PolicyConnection(
                    source=selector_desc,
                    destination=dest,
                    ports=ports,
                    direction="egress",
                    policy_name=pol.name,
                ))

    return connections


def generate_mermaid(policies: list, workloads: list) -> str:
    """Generate a Mermaid flowchart diagram from NetworkPolicies."""
    connections = build_connections(policies, workloads)

    lines = [
        "graph LR",
        "    classDef pod fill:#3b82f6,stroke:#1d4ed8,color:#fff,rx:8",
        "    classDef ns fill:#8b5cf6,stroke:#6d28d9,color:#fff,rx:8",
        "    classDef external fill:#ef4444,stroke:#b91c1c,color:#fff,rx:8",
        "    classDef deny fill:#991b1b,stroke:#7f1d1d,color:#fff,rx:8",
        "",
    ]

    node_ids = {}
    node_counter = [0]

    def get_node_id(label: str) -> str:
        if label not in node_ids:
            node_ids[label] = f"N{node_counter[0]}"
            node_counter[0] += 1
        return node_ids[label]

    # Track which nodes are used
    used_nodes = set()

    # Add deny policies (default-deny)
    for pol in policies:
        is_deny_ingress = ("Ingress" in pol.policy_types and not pol.ingress_rules)
        is_deny_egress = ("Egress" in pol.policy_types and not pol.egress_rules)

        selector_desc = _describe_selector(pol.pod_selector, pol.namespace)
        nid = get_node_id(selector_desc)

        if is_deny_ingress:
            deny_id = get_node_id(f"DENY-IN-{pol.name}")
            lines.append(f'    {deny_id}["🚫 Deny All Ingress"]:::deny')
            lines.append(f"    {deny_id} -.->|{pol.name}| {nid}")
            used_nodes.add(deny_id)
            used_nodes.add(nid)

        if is_deny_egress:
            deny_id = get_node_id(f"DENY-OUT-{pol.name}")
            lines.append(f'    {deny_id}["🚫 Deny All Egress"]:::deny')
            lines.append(f"    {nid} -.->|{pol.name}| {deny_id}")
            used_nodes.add(deny_id)
            used_nodes.add(nid)

    # Add connections
    for conn in connections:
        src_id = get_node_id(conn.source)
        dst_id = get_node_id(conn.destination)
        port_label = _format_ports(conn.ports)
        arrow = "-->" if conn.direction == "ingress" else "-->"

        lines.append(f"    {src_id} {arrow}|{port_label}| {dst_id}")
        used_nodes.add(src_id)
        used_nodes.add(dst_id)

    # Define node shapes
    for label, nid in node_ids.items():
        if nid in used_nodes and not any(f'    {nid}["' in line or f"    {nid}[" in line for line in lines):
            if "🌐" in label or "External" in label or "0.0.0.0" in label:
                lines.insert(5, f'    {nid}["{label}"]:::external')
            elif "ns:" in label:
                lines.insert(5, f'    {nid}["{label}"]:::ns')
            else:
                lines.insert(5, f'    {nid}["{label}"]:::pod')

    return "\n".join(lines)


def generate_ascii_map(policies: list, workloads: list) -> str:
    """Generate an ASCII traffic map for terminal display."""
    connections = build_connections(policies, workloads)
    lines = []

    if not connections and not policies:
        return "  ⚠️  No NetworkPolicies found — all traffic is unrestricted\n"

    # Group connections by policy
    by_policy = defaultdict(list)
    for conn in connections:
        by_policy[conn.policy_name].append(conn)

    # Show deny policies first
    for pol in policies:
        is_deny = (
            ("Ingress" in pol.policy_types and not pol.ingress_rules) or
            ("Egress" in pol.policy_types and not pol.egress_rules)
        )
        if is_deny:
            selector = _describe_selector(pol.pod_selector, pol.namespace)
            deny_types = []
            if "Ingress" in pol.policy_types and not pol.ingress_rules:
                deny_types.append("Ingress")
            if "Egress" in pol.policy_types and not pol.egress_rules:
                deny_types.append("Egress")
            lines.append(f"  🚫 {pol.name}")
            lines.append(f"     Target: {selector}")
            lines.append(f"     Deny: {' + '.join(deny_types)}")
            lines.append("")

    # Show allow rules
    for policy_name, conns in by_policy.items():
        lines.append(f"  📋 {policy_name}")
        for conn in conns:
            port_str = _format_ports(conn.ports)
            arrow = "→" if conn.direction == "ingress" else "→"
            icon = "🟢" if conn.direction == "ingress" else "🔵"
            lines.append(f"     {icon} {conn.source} {arrow} {conn.destination}  [{port_str}]")
        lines.append("")

    return "\n".join(lines) if lines else "  No traffic connections defined\n"


def _describe_selector(selector: dict, namespace: str) -> str:
    """Describe a pod selector in human-readable form."""
    if not selector:
        return f"All pods (ns:{namespace})"

    match_labels = selector.get("matchLabels", {})
    if not match_labels:
        return f"All pods (ns:{namespace})"

    labels = ", ".join(f"{k}={v}" for k, v in match_labels.items())
    return f"{labels} (ns:{namespace})"


def _describe_peer(peer: dict, default_ns: str, role: str) -> str:
    """Describe a from/to peer in human-readable form."""
    if peer.get("type") == "all":
        return "🌐 Any source" if role == "source" else "🌐 Any destination"

    parts = []

    if "ipBlock" in peer:
        cidr = peer["ipBlock"].get("cidr", "?")
        excepts = peer["ipBlock"].get("except", [])
        desc = f"IP: {cidr}"
        if excepts:
            desc += f" (except {', '.join(excepts)})"
        return desc

    pod_sel = peer.get("podSelector")
    ns_sel = peer.get("namespaceSelector")

    if ns_sel is not None:
        ns_labels = ns_sel.get("matchLabels", {})
        if ns_labels:
            ns_desc = ", ".join(f"{k}={v}" for k, v in ns_labels.items())
            parts.append(f"ns:[{ns_desc}]")
        else:
            parts.append("ns:[all]")

    if pod_sel is not None:
        pod_labels = pod_sel.get("matchLabels", {})
        if pod_labels:
            pod_desc = ", ".join(f"{k}={v}" for k, v in pod_labels.items())
            parts.append(f"pods:[{pod_desc}]")
        else:
            parts.append("pods:[all]")

    if not parts:
        return "Unknown peer"

    return " ".join(parts)


def _format_ports(ports: list) -> str:
    """Format a list of port specs into a string."""
    if not ports:
        return "ALL"

    parts = []
    for p in ports:
        port = p.get("port", "ALL")
        protocol = p.get("protocol", "TCP")
        end_port = p.get("endPort")

        if port == "ALL":
            parts.append("ALL")
        elif end_port:
            parts.append(f"{port}-{end_port}/{protocol}")
        else:
            parts.append(f"{port}/{protocol}")

    return ", ".join(parts)
