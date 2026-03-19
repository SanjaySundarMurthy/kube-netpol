"""Traffic simulator — simulate traffic flows against NetworkPolicies."""
from kube_netpol.models import NetworkPolicy, TrafficFlow, TrafficVerdict


def simulate_traffic(policies: list, flows: list) -> list:
    """Simulate traffic flows against the given NetworkPolicies.

    For each flow, determine if it would be ALLOWED, DENIED, or UNKNOWN.

    NetworkPolicy semantics:
    - If NO policy selects a pod, all traffic is allowed (no isolation)
    - If ANY policy selects a pod, only traffic explicitly allowed by rules is permitted
    - Policies are additive: if any policy allows the traffic, it's allowed
    """
    results = []

    for flow in flows:
        result = _evaluate_flow(policies, flow)
        results.append(result)

    return results


def _evaluate_flow(policies: list, flow: TrafficFlow) -> TrafficFlow:
    """Evaluate a single traffic flow against all policies."""
    # Find policies that select the destination pod (for ingress)
    dest_policies = [
        p for p in policies
        if p.namespace == flow.dest_namespace
        and _selector_matches(p.pod_selector, flow.dest_labels)
    ]

    # Find policies that select the source pod (for egress)
    src_policies = [
        p for p in policies
        if p.namespace == flow.source_namespace
        and _selector_matches(p.pod_selector, flow.source_labels)
    ]

    # If no policy selects the destination pod for ingress, ingress is allowed
    ingress_policies = [p for p in dest_policies if "Ingress" in p.policy_types]
    if not ingress_policies:
        ingress_verdict = TrafficVerdict.ALLOW
        ingress_reason = "No ingress policy selects destination pod"
    else:
        ingress_verdict, ingress_reason = _check_ingress(ingress_policies, flow)

    # If no policy selects the source pod for egress, egress is allowed
    egress_policies = [p for p in src_policies if "Egress" in p.policy_types]
    if not egress_policies:
        egress_verdict = TrafficVerdict.ALLOW
        egress_reason = "No egress policy selects source pod"
    else:
        egress_verdict, egress_reason = _check_egress(egress_policies, flow)

    # Traffic is allowed only if BOTH ingress and egress allow it
    if ingress_verdict == TrafficVerdict.ALLOW and egress_verdict == TrafficVerdict.ALLOW:
        flow.verdict = TrafficVerdict.ALLOW
        flow.matched_rule = f"Ingress: {ingress_reason} | Egress: {egress_reason}"
    elif ingress_verdict == TrafficVerdict.DENY:
        flow.verdict = TrafficVerdict.DENY
        flow.matched_rule = f"Ingress DENIED: {ingress_reason}"
    elif egress_verdict == TrafficVerdict.DENY:
        flow.verdict = TrafficVerdict.DENY
        flow.matched_rule = f"Egress DENIED: {egress_reason}"
    else:
        flow.verdict = TrafficVerdict.UNKNOWN
        flow.matched_rule = "Unable to determine verdict"

    return flow


def _check_ingress(policies: list, flow: TrafficFlow):
    """Check if ingress is allowed by any policy."""
    for pol in policies:
        for rule in pol.ingress_rules:
            from_peers = rule.get("from", [])
            ports = rule.get("ports", [])

            # Check if source matches 'from' peers
            if _source_matches_peers(from_peers, flow):
                # Check if port matches
                if _port_matches(ports, flow.port, flow.protocol):
                    return TrafficVerdict.ALLOW, f"Allowed by '{pol.name}'"

    return TrafficVerdict.DENY, f"No ingress rule allows this traffic"


def _check_egress(policies: list, flow: TrafficFlow):
    """Check if egress is allowed by any policy."""
    for pol in policies:
        for rule in pol.egress_rules:
            to_peers = rule.get("to", [])
            ports = rule.get("ports", [])

            # Check if destination matches 'to' peers
            if _dest_matches_peers(to_peers, flow):
                if _port_matches(ports, flow.port, flow.protocol):
                    return TrafficVerdict.ALLOW, f"Allowed by '{pol.name}'"

    return TrafficVerdict.DENY, f"No egress rule allows this traffic"


def _selector_matches(selector: dict, labels: dict) -> bool:
    """Check if a pod selector matches the given labels."""
    if not selector:
        return True  # Empty selector matches all

    match_labels = selector.get("matchLabels", {})
    if not match_labels:
        return True  # No matchLabels = match all

    return all(labels.get(k) == v for k, v in match_labels.items())


def _source_matches_peers(peers: list, flow: TrafficFlow) -> bool:
    """Check if the source of a flow matches any of the 'from' peers."""
    if not peers:
        return True  # No 'from' field = allow all

    for peer in peers:
        if peer.get("type") == "all":
            return True

        pod_sel = peer.get("podSelector")
        ns_sel = peer.get("namespaceSelector")
        ip_block = peer.get("ipBlock")

        # podSelector only (same namespace)
        if pod_sel is not None and ns_sel is None and ip_block is None:
            if flow.source_namespace == flow.dest_namespace:
                if _selector_matches(pod_sel, flow.source_labels):
                    return True

        # namespaceSelector only (all pods in matching namespaces)
        elif ns_sel is not None and pod_sel is None and ip_block is None:
            # We'd need namespace labels to fully check this
            # For simulation, check if namespace matches
            ns_labels = ns_sel.get("matchLabels", {})
            if not ns_labels:
                return True  # Empty = all namespaces

        # Both podSelector and namespaceSelector
        elif pod_sel is not None and ns_sel is not None:
            ns_labels = ns_sel.get("matchLabels", {})
            if (not ns_labels or True) and _selector_matches(pod_sel, flow.source_labels):
                return True

        # ipBlock
        elif ip_block:
            # For simulation, we only check pod-to-pod traffic
            pass

    return False


def _dest_matches_peers(peers: list, flow: TrafficFlow) -> bool:
    """Check if the destination of a flow matches any of the 'to' peers."""
    if not peers:
        return True

    for peer in peers:
        if peer.get("type") == "all":
            return True

        pod_sel = peer.get("podSelector")
        ns_sel = peer.get("namespaceSelector")
        ip_block = peer.get("ipBlock")

        if pod_sel is not None and ns_sel is None and ip_block is None:
            if flow.source_namespace == flow.dest_namespace:
                if _selector_matches(pod_sel, flow.dest_labels):
                    return True
        elif ns_sel is not None and pod_sel is None:
            ns_labels = ns_sel.get("matchLabels", {})
            if not ns_labels:
                return True
        elif pod_sel is not None and ns_sel is not None:
            if _selector_matches(pod_sel, flow.dest_labels):
                return True
        elif ip_block:
            pass

    return False


def _port_matches(ports: list, target_port, target_protocol: str) -> bool:
    """Check if the target port matches any port in the rule."""
    if not ports:
        return True  # No ports field = all ports

    for p in ports:
        rule_port = p.get("port")
        rule_protocol = p.get("protocol", "TCP")
        end_port = p.get("endPort")

        if rule_port == "ALL":
            return True

        # Protocol must match
        if target_protocol and rule_protocol != target_protocol:
            continue

        if target_port is None:
            return True  # No specific port requested

        if isinstance(rule_port, int) and isinstance(target_port, int):
            if end_port:
                if rule_port <= target_port <= end_port:
                    return True
            elif rule_port == target_port:
                return True

        # Named port matching
        if isinstance(rule_port, str) and isinstance(target_port, str):
            if rule_port == target_port:
                return True

    return False
