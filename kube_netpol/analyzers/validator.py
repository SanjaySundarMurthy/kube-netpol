"""NetworkPolicy validator — 50+ rules for security, correctness, and best practices."""
import re
from collections import Counter

from kube_netpol.models import Issue, NetworkPolicy, Severity

# RFC 1918 private ranges
PRIVATE_CIDRS = [
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
]

# Known dangerous port ranges
DANGEROUS_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    445: "SMB",
    3389: "RDP",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5432: "PostgreSQL",
    3306: "MySQL",
    1433: "MSSQL",
    11211: "Memcached",
    2379: "etcd",
    2380: "etcd peer",
    6443: "Kubernetes API",
    10250: "kubelet",
    10255: "kubelet read-only",
}

# Kubernetes internal CIDRs
K8S_METADATA_CIDR = "169.254.169.254/32"


def validate_policies(policies: list, workloads: list) -> list:
    """Run all validation rules against the parsed policies."""
    issues = []

    if not policies:
        issues.append(Issue(
            rule_id="KNP-001",
            severity=Severity.HIGH,
            message="No NetworkPolicies found — all pod traffic is unrestricted",
            file_path="(none)",
            suggestion="Create NetworkPolicies to restrict traffic between pods. Use 'kube-netpol generate' for templates",
            doc_url="https://kubernetes.io/docs/concepts/services-networking/network-policies/",
        ))
        return issues

    # Per-policy checks
    for pol in policies:
        _check_policy_structure(pol, issues)
        _check_pod_selector(pol, issues)
        _check_policy_types(pol, issues)
        _check_ingress_rules(pol, issues)
        _check_egress_rules(pol, issues)
        _check_ip_blocks(pol, issues)
        _check_port_rules(pol, issues)
        _check_labels_annotations(pol, issues)

    # Cross-policy checks
    _check_duplicate_policies(policies, issues)
    _check_conflicting_policies(policies, issues)
    _check_overlapping_selectors(policies, issues)
    _check_default_deny_exists(policies, issues)
    _check_coverage(policies, workloads, issues)
    _check_namespace_isolation(policies, issues)
    _check_dns_egress(policies, issues)

    return issues


def _check_policy_structure(pol: NetworkPolicy, issues: list):
    """Structural validation of the policy."""
    # KNP-002: Name should follow conventions
    name = pol.name
    if not re.match(r"^[a-z][a-z0-9\-]*$", name):
        issues.append(Issue(
            rule_id="KNP-002",
            severity=Severity.LOW,
            message=f"Policy name '{name}' should use lowercase, digits, and dashes only",
            file_path=pol.file_path,
            policy_name=name,
            suggestion=f"Rename to follow DNS naming conventions (e.g., '{name.lower().replace('_', '-')}')",
        ))

    # KNP-003: Name length
    if len(name) > 63:
        issues.append(Issue(
            rule_id="KNP-003",
            severity=Severity.HIGH,
            message=f"Policy name '{name}' exceeds 63 characters (DNS label limit)",
            file_path=pol.file_path,
            policy_name=name,
            suggestion="Shorten the policy name to 63 characters or fewer",
        ))

    # KNP-004: Empty spec
    if not pol.ingress_rules and not pol.egress_rules and not pol.policy_types:
        issues.append(Issue(
            rule_id="KNP-004",
            severity=Severity.MEDIUM,
            message=f"Policy '{name}' has empty spec — no rules and no policyTypes declared",
            file_path=pol.file_path,
            policy_name=name,
            suggestion="Add ingress/egress rules or declare policyTypes explicitly",
        ))


def _check_pod_selector(pol: NetworkPolicy, issues: list):
    """Validate pod selector configuration."""
    selector = pol.pod_selector
    match_labels = selector.get("matchLabels", {}) if selector else {}
    match_expressions = selector.get("matchExpressions", []) if selector else []

    # KNP-005: Empty podSelector (selects ALL pods)
    if not match_labels and not match_expressions:
        # This is intentional for default deny — but worth noting
        issues.append(Issue(
            rule_id="KNP-005",
            severity=Severity.INFO,
            message=f"Policy '{pol.name}' has empty podSelector — applies to ALL pods in namespace '{pol.namespace}'",
            file_path=pol.file_path,
            policy_name=pol.name,
            suggestion="This is correct for default-deny policies. For targeted policies, add matchLabels",
        ))

    # KNP-006: matchExpressions with invalid operator
    for expr in match_expressions:
        if isinstance(expr, dict):
            op = expr.get("operator", "")
            valid_ops = {"In", "NotIn", "Exists", "DoesNotExist"}
            if op and op not in valid_ops:
                issues.append(Issue(
                    rule_id="KNP-006",
                    severity=Severity.HIGH,
                    message=f"Policy '{pol.name}' has invalid matchExpression operator: '{op}'",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion=f"Use one of: {', '.join(sorted(valid_ops))}",
                ))


def _check_policy_types(pol: NetworkPolicy, issues: list):
    """Validate policyTypes field."""
    # KNP-007: policyTypes should be explicitly set
    if not pol.policy_types:
        issues.append(Issue(
            rule_id="KNP-007",
            severity=Severity.MEDIUM,
            message=f"Policy '{pol.name}' does not explicitly declare policyTypes",
            file_path=pol.file_path,
            policy_name=pol.name,
            suggestion="Explicitly set policyTypes: ['Ingress'], ['Egress'], or ['Ingress', 'Egress']",
            doc_url="https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors",
        ))

    # KNP-008: policyTypes has invalid value
    valid_types = {"Ingress", "Egress"}
    for pt in pol.policy_types:
        if pt not in valid_types:
            issues.append(Issue(
                rule_id="KNP-008",
                severity=Severity.HIGH,
                message=f"Policy '{pol.name}' has invalid policyType: '{pt}'",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Valid policyTypes are 'Ingress' and 'Egress'",
            ))

    # KNP-009: Egress declared but no egress rules
    if "Egress" in pol.policy_types and not pol.egress_rules:
        issues.append(Issue(
            rule_id="KNP-009",
            severity=Severity.MEDIUM,
            message=f"Policy '{pol.name}' declares Egress policyType but has no egress rules — denies ALL egress",
            file_path=pol.file_path,
            policy_name=pol.name,
            suggestion="This creates a default-deny egress. If intentional, add a comment. Otherwise, add egress rules",
        ))

    # KNP-010: Ingress declared but no ingress rules
    if "Ingress" in pol.policy_types and not pol.ingress_rules:
        issues.append(Issue(
            rule_id="KNP-010",
            severity=Severity.MEDIUM,
            message=f"Policy '{pol.name}' declares Ingress policyType but has no ingress rules — denies ALL ingress",
            file_path=pol.file_path,
            policy_name=pol.name,
            suggestion="This creates a default-deny ingress. If intentional, document the intent",
        ))


def _check_ingress_rules(pol: NetworkPolicy, issues: list):
    """Validate ingress rules."""
    for i, rule in enumerate(pol.ingress_rules):
        from_peers = rule.get("from", [])
        ports = rule.get("ports", [])

        # KNP-011: Ingress from all sources (no 'from' field)
        if any(p.get("type") == "all" for p in from_peers):
            issues.append(Issue(
                rule_id="KNP-011",
                severity=Severity.HIGH,
                message=f"Policy '{pol.name}' ingress rule #{i+1} allows traffic from ALL sources",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Restrict ingress with podSelector, namespaceSelector, or ipBlock",
            ))

        # KNP-012: Ingress on all ports
        if any(p.get("port") == "ALL" for p in ports):
            issues.append(Issue(
                rule_id="KNP-012",
                severity=Severity.MEDIUM,
                message=f"Policy '{pol.name}' ingress rule #{i+1} allows ALL ports",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Restrict to specific ports needed by the application",
            ))

        # KNP-013: Empty from (combined with podSelector + namespaceSelector)
        for peer in from_peers:
            if "podSelector" in peer and "namespaceSelector" in peer:
                pod_sel = peer["podSelector"]
                ns_sel = peer["namespaceSelector"]
                if not pod_sel.get("matchLabels") and not ns_sel.get("matchLabels"):
                    issues.append(Issue(
                        rule_id="KNP-013",
                        severity=Severity.HIGH,
                        message=f"Policy '{pol.name}' ingress rule #{i+1} has empty podSelector AND namespaceSelector — allows ALL pods in ALL namespaces",
                        file_path=pol.file_path,
                        policy_name=pol.name,
                        suggestion="Add matchLabels to podSelector or namespaceSelector to restrict traffic",
                    ))


def _check_egress_rules(pol: NetworkPolicy, issues: list):
    """Validate egress rules."""
    for i, rule in enumerate(pol.egress_rules):
        to_peers = rule.get("to", [])
        ports = rule.get("ports", [])

        # KNP-014: Egress to all destinations
        if any(p.get("type") == "all" for p in to_peers):
            issues.append(Issue(
                rule_id="KNP-014",
                severity=Severity.HIGH,
                message=f"Policy '{pol.name}' egress rule #{i+1} allows traffic to ALL destinations",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Restrict egress with podSelector, namespaceSelector, or ipBlock",
            ))

        # KNP-015: Egress on all ports
        if any(p.get("port") == "ALL" for p in ports):
            issues.append(Issue(
                rule_id="KNP-015",
                severity=Severity.MEDIUM,
                message=f"Policy '{pol.name}' egress rule #{i+1} allows ALL ports",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Restrict to specific ports needed (e.g., 443 for HTTPS, 53 for DNS)",
            ))


def _check_ip_blocks(pol: NetworkPolicy, issues: list):
    """Validate ipBlock configurations."""
    all_rules = [(r, "ingress") for r in pol.ingress_rules] + [(r, "egress") for r in pol.egress_rules]

    for rule, direction in all_rules:
        peers_key = "from" if direction == "ingress" else "to"
        peers = rule.get(peers_key, [])

        for peer in peers:
            ip_block = peer.get("ipBlock")
            if not ip_block:
                continue

            cidr = ip_block.get("cidr", "")
            excepts = ip_block.get("except", [])

            # KNP-016: 0.0.0.0/0 allows all IPs
            if cidr == "0.0.0.0/0":
                issues.append(Issue(
                    rule_id="KNP-016",
                    severity=Severity.HIGH,
                    message=f"Policy '{pol.name}' {direction} uses 0.0.0.0/0 — allows ALL IPv4 addresses",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion="Use more specific CIDR ranges. Add 'except' to exclude private/internal ranges",
                ))

            # KNP-017: ::/0 allows all IPv6
            if cidr == "::/0":
                issues.append(Issue(
                    rule_id="KNP-017",
                    severity=Severity.HIGH,
                    message=f"Policy '{pol.name}' {direction} uses ::/0 — allows ALL IPv6 addresses",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion="Use specific IPv6 CIDR ranges",
                ))

            # KNP-018: Invalid CIDR format
            if cidr and not _is_valid_cidr(cidr):
                issues.append(Issue(
                    rule_id="KNP-018",
                    severity=Severity.HIGH,
                    message=f"Policy '{pol.name}' has invalid CIDR: '{cidr}'",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion="Use valid CIDR notation (e.g., '10.0.0.0/8', '192.168.1.0/24')",
                ))

            # KNP-019: except CIDR not within the main CIDR
            for exc in excepts:
                if not _is_valid_cidr(exc):
                    issues.append(Issue(
                        rule_id="KNP-019",
                        severity=Severity.HIGH,
                        message=f"Policy '{pol.name}' has invalid except CIDR: '{exc}'",
                        file_path=pol.file_path,
                        policy_name=pol.name,
                        suggestion="Except CIDRs must be valid and within the main CIDR range",
                    ))

            # KNP-020: Cloud metadata endpoint access
            if cidr == "0.0.0.0/0" and direction == "egress":
                if K8S_METADATA_CIDR not in excepts and "169.254.169.254" not in str(excepts):
                    issues.append(Issue(
                        rule_id="KNP-020",
                        severity=Severity.CRITICAL,
                        message=f"Policy '{pol.name}' egress to 0.0.0.0/0 does not exclude cloud metadata endpoint (169.254.169.254/32)",
                        file_path=pol.file_path,
                        policy_name=pol.name,
                        suggestion="Add '169.254.169.254/32' to ipBlock.except to prevent SSRF attacks on cloud metadata",
                        doc_url="https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                    ))


def _check_port_rules(pol: NetworkPolicy, issues: list):
    """Validate port configurations."""
    all_rules = [(r, "ingress") for r in pol.ingress_rules] + [(r, "egress") for r in pol.egress_rules]

    for rule, direction in all_rules:
        ports = rule.get("ports", [])
        for p in ports:
            port_num = p.get("port")
            protocol = p.get("protocol", "TCP")
            end_port = p.get("endPort")

            if isinstance(port_num, int):
                # KNP-021: Dangerous port exposed
                if port_num in DANGEROUS_PORTS:
                    svc_name = DANGEROUS_PORTS[port_num]
                    severity = Severity.HIGH if port_num in (2379, 2380, 6443, 10250, 10255) else Severity.MEDIUM
                    issues.append(Issue(
                        rule_id="KNP-021",
                        severity=severity,
                        message=f"Policy '{pol.name}' {direction} allows port {port_num} ({svc_name})",
                        file_path=pol.file_path,
                        policy_name=pol.name,
                        suggestion=f"Ensure port {port_num} ({svc_name}) access is intentional and restricted to authorized sources",
                    ))

                # KNP-022: Port range check
                if port_num < 1 or port_num > 65535:
                    issues.append(Issue(
                        rule_id="KNP-022",
                        severity=Severity.HIGH,
                        message=f"Policy '{pol.name}' has invalid port number: {port_num}",
                        file_path=pol.file_path,
                        policy_name=pol.name,
                        suggestion="Port numbers must be between 1 and 65535",
                    ))

            # KNP-023: endPort without port
            if end_port and not port_num:
                issues.append(Issue(
                    rule_id="KNP-023",
                    severity=Severity.HIGH,
                    message=f"Policy '{pol.name}' has endPort without port — this is invalid",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion="Specify 'port' when using 'endPort' for port ranges",
                ))

            # KNP-024: Large port range
            if isinstance(port_num, int) and isinstance(end_port, int):
                range_size = end_port - port_num
                if range_size > 1000:
                    issues.append(Issue(
                        rule_id="KNP-024",
                        severity=Severity.MEDIUM,
                        message=f"Policy '{pol.name}' has large port range: {port_num}-{end_port} ({range_size} ports)",
                        file_path=pol.file_path,
                        policy_name=pol.name,
                        suggestion="Use the narrowest port range possible. Large ranges increase attack surface",
                    ))

            # KNP-025: SCTP protocol warning
            if protocol == "SCTP":
                issues.append(Issue(
                    rule_id="KNP-025",
                    severity=Severity.INFO,
                    message=f"Policy '{pol.name}' uses SCTP protocol — ensure your CNI supports it",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion="Not all CNI plugins support SCTP. Verify with your cluster admin",
                ))


def _check_labels_annotations(pol: NetworkPolicy, issues: list):
    """Check labels and annotations best practices."""
    # KNP-026: Missing standard labels
    if pol.labels:
        has_standard = any(k.startswith("app.kubernetes.io/") for k in pol.labels)
        if not has_standard:
            issues.append(Issue(
                rule_id="KNP-026",
                severity=Severity.LOW,
                message=f"Policy '{pol.name}' does not use standard Kubernetes labels",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Add 'app.kubernetes.io/name' and 'app.kubernetes.io/part-of' labels for organization",
            ))
    else:
        issues.append(Issue(
            rule_id="KNP-026",
            severity=Severity.LOW,
            message=f"Policy '{pol.name}' has no labels",
            file_path=pol.file_path,
            policy_name=pol.name,
            suggestion="Add labels for organization and management (e.g., 'app.kubernetes.io/name')",
        ))


def _check_duplicate_policies(policies: list, issues: list):
    """KNP-027: Check for duplicate policy names in the same namespace."""
    key_counts = Counter((p.name, p.namespace) for p in policies)
    for (name, ns), count in key_counts.items():
        if count > 1:
            issues.append(Issue(
                rule_id="KNP-027",
                severity=Severity.HIGH,
                message=f"Duplicate policy name '{name}' in namespace '{ns}' ({count} definitions)",
                file_path="(multiple files)",
                policy_name=name,
                suggestion="Each NetworkPolicy must have a unique name within a namespace",
            ))


def _check_conflicting_policies(policies: list, issues: list):
    """KNP-028: Check for policies with identical selectors but different rules."""
    by_selector = {}
    for pol in policies:
        key = (pol.namespace, str(sorted(pol.pod_selector.items()) if isinstance(pol.pod_selector, dict) else []))
        by_selector.setdefault(key, []).append(pol)

    for key, pols in by_selector.items():
        if len(pols) > 1:
            names = [p.name for p in pols]
            ns = pols[0].namespace
            issues.append(Issue(
                rule_id="KNP-028",
                severity=Severity.MEDIUM,
                message=f"Multiple policies target the same pods in namespace '{ns}': {', '.join(names)}",
                file_path="(multiple files)",
                suggestion="Multiple policies on same pods are additive (union). Ensure this is intentional",
                doc_url="https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors",
            ))


def _check_overlapping_selectors(policies: list, issues: list):
    """KNP-029: Detect overly broad selectors that overlap with specific ones."""
    for pol in policies:
        selector = pol.pod_selector
        if isinstance(selector, dict) and not selector.get("matchLabels") and not selector.get("matchExpressions"):
            # This is a catch-all policy
            specific_policies = [
                p for p in policies
                if p.namespace == pol.namespace and p.name != pol.name
                and isinstance(p.pod_selector, dict)
                and (p.pod_selector.get("matchLabels") or p.pod_selector.get("matchExpressions"))
            ]
            if specific_policies:
                names = [p.name for p in specific_policies]
                issues.append(Issue(
                    rule_id="KNP-029",
                    severity=Severity.INFO,
                    message=f"Catch-all policy '{pol.name}' overlaps with specific policies: {', '.join(names)}",
                    file_path=pol.file_path,
                    policy_name=pol.name,
                    suggestion="NetworkPolicies are additive. The catch-all and specific policies work together",
                ))


def _check_default_deny_exists(policies: list, issues: list):
    """KNP-030/031: Check for default-deny policies."""
    namespaces = set(p.namespace for p in policies)

    for ns in namespaces:
        ns_policies = [p for p in policies if p.namespace == ns]

        # Check for default-deny ingress
        has_deny_ingress = any(
            _is_default_deny(p, "Ingress") for p in ns_policies
        )
        if not has_deny_ingress:
            issues.append(Issue(
                rule_id="KNP-030",
                severity=Severity.HIGH,
                message=f"No default-deny ingress policy in namespace '{ns}'",
                file_path="(none)",
                suggestion=f"Create a default-deny ingress policy for namespace '{ns}' to block unauthorized inbound traffic",
                doc_url="https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-ingress-traffic",
            ))

        # Check for default-deny egress
        has_deny_egress = any(
            _is_default_deny(p, "Egress") for p in ns_policies
        )
        if not has_deny_egress:
            issues.append(Issue(
                rule_id="KNP-031",
                severity=Severity.MEDIUM,
                message=f"No default-deny egress policy in namespace '{ns}'",
                file_path="(none)",
                suggestion=f"Create a default-deny egress policy for namespace '{ns}' to control outbound traffic",
                doc_url="https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-egress-traffic",
            ))


def _check_coverage(policies: list, workloads: list, issues: list):
    """KNP-032: Check if all workloads are covered by at least one policy."""
    for wl in workloads:
        if wl["kind"] == "Service":
            continue

        wl_labels = wl.get("labels", {})
        wl_ns = wl.get("namespace", "default")
        covered = False

        for pol in policies:
            if pol.namespace != wl_ns:
                continue
            selector = pol.pod_selector
            if not isinstance(selector, dict):
                continue
            match_labels = selector.get("matchLabels", {})
            if not match_labels:
                covered = True
                break
            if all(wl_labels.get(k) == v for k, v in match_labels.items()):
                covered = True
                break

        if not covered:
            issues.append(Issue(
                rule_id="KNP-032",
                severity=Severity.MEDIUM,
                message=f"Workload '{wl['name']}' ({wl['kind']}) in namespace '{wl_ns}' is not covered by any NetworkPolicy",
                file_path=wl.get("file", ""),
                suggestion=f"Create a NetworkPolicy targeting labels {wl_labels} in namespace '{wl_ns}'",
            ))


def _check_namespace_isolation(policies: list, issues: list):
    """KNP-033: Check for cross-namespace access patterns."""
    for pol in policies:
        for rule in pol.ingress_rules:
            for peer in rule.get("from", []):
                if "namespaceSelector" in peer and "podSelector" not in peer:
                    ns_sel = peer["namespaceSelector"]
                    if not ns_sel.get("matchLabels") and not ns_sel.get("matchExpressions"):
                        issues.append(Issue(
                            rule_id="KNP-033",
                            severity=Severity.HIGH,
                            message=f"Policy '{pol.name}' allows ingress from ALL namespaces (empty namespaceSelector)",
                            file_path=pol.file_path,
                            policy_name=pol.name,
                            suggestion="Add matchLabels to namespaceSelector to restrict to specific namespaces",
                        ))


def _check_dns_egress(policies: list, issues: list):
    """KNP-034: Check if DNS egress is allowed when egress is restricted."""
    for pol in policies:
        if "Egress" not in pol.policy_types:
            continue

        if not pol.egress_rules:
            # Default deny egress — DNS is blocked too
            issues.append(Issue(
                rule_id="KNP-034",
                severity=Severity.HIGH,
                message=f"Policy '{pol.name}' denies all egress including DNS (port 53) — pods will fail name resolution",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Add an egress rule allowing UDP port 53 to kube-system namespace for DNS resolution",
            ))
            continue

        # Check if any rule allows port 53
        allows_dns = False
        for rule in pol.egress_rules:
            ports = rule.get("ports", [])
            for p in ports:
                port = p.get("port")
                if port == 53 or port == "ALL":
                    allows_dns = True
                    break
            if allows_dns:
                break

        if not allows_dns:
            issues.append(Issue(
                rule_id="KNP-034",
                severity=Severity.HIGH,
                message=f"Policy '{pol.name}' restricts egress but does not allow DNS (port 53/UDP)",
                file_path=pol.file_path,
                policy_name=pol.name,
                suggestion="Add an egress rule: port 53, protocol UDP, to kube-system for DNS resolution",
            ))


def _is_default_deny(pol: NetworkPolicy, direction: str) -> bool:
    """Check if a policy is a default-deny for the given direction."""
    selector = pol.pod_selector
    is_catch_all = (
        not isinstance(selector, dict)
        or (not selector.get("matchLabels") and not selector.get("matchExpressions"))
    )

    if not is_catch_all:
        return False

    if direction == "Ingress":
        return "Ingress" in pol.policy_types and not pol.ingress_rules
    elif direction == "Egress":
        return "Egress" in pol.policy_types and not pol.egress_rules

    return False


def _is_valid_cidr(cidr: str) -> bool:
    """Basic CIDR validation."""
    if "/" not in cidr:
        return False
    parts = cidr.split("/")
    if len(parts) != 2:
        return False
    try:
        prefix_len = int(parts[1])
    except ValueError:
        return False

    ip_part = parts[0]
    if ":" in ip_part:
        # IPv6
        return 0 <= prefix_len <= 128
    else:
        # IPv4
        octets = ip_part.split(".")
        if len(octets) != 4:
            return False
        for o in octets:
            try:
                val = int(o)
                if val < 0 or val > 255:
                    return False
            except ValueError:
                return False
        return 0 <= prefix_len <= 32
