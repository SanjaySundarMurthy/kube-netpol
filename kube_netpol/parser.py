"""YAML parser — reads Kubernetes manifests and extracts NetworkPolicies + workloads."""
import os
from typing import Tuple

import yaml

from kube_netpol.models import NetworkPolicy


def parse_manifests(path: str) -> Tuple[list, list]:
    """Parse all YAML files from a path and return (network_policies, workloads).

    Args:
        path: File or directory path containing Kubernetes manifests.

    Returns:
        Tuple of (list of NetworkPolicy objects, list of workload dicts).
    """
    yaml_files = _collect_yaml_files(path)
    policies = []
    workloads = []

    for fpath in yaml_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        # Handle multi-document YAML files
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            api_version = doc.get("apiVersion", "")
            metadata = doc.get("metadata", {}) or {}
            spec = doc.get("spec", {}) or {}

            if kind == "NetworkPolicy" and "networking.k8s.io" in api_version:
                pol = _parse_network_policy(doc, fpath)
                if pol:
                    policies.append(pol)

            elif kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                          "Job", "CronJob", "Pod"):
                workloads.append({
                    "kind": kind,
                    "name": metadata.get("name", "unknown"),
                    "namespace": metadata.get("namespace", "default"),
                    "labels": _extract_pod_labels(doc),
                    "file": fpath,
                })

            elif kind == "Service":
                workloads.append({
                    "kind": "Service",
                    "name": metadata.get("name", "unknown"),
                    "namespace": metadata.get("namespace", "default"),
                    "labels": spec.get("selector", {}),
                    "ports": _extract_service_ports(spec),
                    "file": fpath,
                })

    return policies, workloads


def _collect_yaml_files(path: str) -> list:
    """Collect all YAML files from a file or directory."""
    path = os.path.abspath(path)
    if os.path.isfile(path):
        return [path]

    yaml_files = []
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith((".yaml", ".yml")) and not f.startswith("."):
                yaml_files.append(os.path.join(root, f))
    return sorted(yaml_files)


def _parse_network_policy(doc: dict, file_path: str) -> NetworkPolicy:
    """Parse a single NetworkPolicy document."""
    metadata = doc.get("metadata", {}) or {}
    spec = doc.get("spec", {}) or {}

    pol = NetworkPolicy(
        name=metadata.get("name", "unnamed"),
        namespace=metadata.get("namespace", "default"),
        pod_selector=spec.get("podSelector", {}) or {},
        policy_types=spec.get("policyTypes", []) or [],
        labels=metadata.get("labels", {}) or {},
        annotations=metadata.get("annotations", {}) or {},
        file_path=file_path,
        raw=doc,
    )

    # Parse ingress rules
    for rule in (spec.get("ingress") or []):
        if not isinstance(rule, dict):
            continue
        parsed_rule = {
            "ports": _parse_ports(rule.get("ports")),
            "from": _parse_peers(rule.get("from")),
        }
        pol.ingress_rules.append(parsed_rule)

    # Parse egress rules
    for rule in (spec.get("egress") or []):
        if not isinstance(rule, dict):
            continue
        parsed_rule = {
            "ports": _parse_ports(rule.get("ports")),
            "to": _parse_peers(rule.get("to")),
        }
        pol.egress_rules.append(parsed_rule)

    return pol


def _parse_ports(ports) -> list:
    """Parse port specifications."""
    if not ports:
        return [{"port": "ALL", "protocol": "ALL"}]
    result = []
    for p in ports:
        if isinstance(p, dict):
            result.append({
                "port": p.get("port", "ALL"),
                "protocol": p.get("protocol", "TCP"),
                "endPort": p.get("endPort"),
            })
    return result


def _parse_peers(peers) -> list:
    """Parse from/to peer selectors."""
    if peers is None:
        return [{"type": "all"}]  # No restriction = all
    if not peers:
        return []  # Empty array = none

    result = []
    for peer in peers:
        if not isinstance(peer, dict):
            continue

        entry = {}
        if "podSelector" in peer:
            entry["podSelector"] = peer["podSelector"] or {}
        if "namespaceSelector" in peer:
            entry["namespaceSelector"] = peer["namespaceSelector"] or {}
        if "ipBlock" in peer:
            ip_block = peer["ipBlock"] or {}
            entry["ipBlock"] = {
                "cidr": ip_block.get("cidr", ""),
                "except": ip_block.get("except", []),
            }
        result.append(entry)
    return result


def _extract_pod_labels(doc: dict) -> dict:
    """Extract pod labels from a workload spec."""
    kind = doc.get("kind", "")
    spec = doc.get("spec", {}) or {}

    if kind == "Pod":
        return (doc.get("metadata", {}) or {}).get("labels", {}) or {}

    # Deployment, StatefulSet, etc.
    template = spec.get("template", {}) or {}
    template_meta = template.get("metadata", {}) or {}
    return template_meta.get("labels", {}) or {}


def _extract_service_ports(spec: dict) -> list:
    """Extract port info from a Service spec."""
    result = []
    for p in (spec.get("ports") or []):
        if isinstance(p, dict):
            result.append({
                "port": p.get("port"),
                "targetPort": p.get("targetPort"),
                "protocol": p.get("protocol", "TCP"),
                "name": p.get("name", ""),
            })
    return result
