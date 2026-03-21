"""Tests for kube-netpol traffic simulator."""
from kube_netpol.analyzers.simulator import simulate_traffic
from kube_netpol.models import TrafficFlow, TrafficVerdict
from kube_netpol.parser import parse_manifests


class TestSimulateTraffic:
    def test_simulate_with_policies(self, good_manifests):
        policies, workloads = parse_manifests(good_manifests)
        flow = TrafficFlow(
            source_pod="frontend",
            source_namespace="default",
            source_labels={"app": "frontend"},
            dest_pod="web",
            dest_namespace="default",
            dest_labels={"app": "web"},
            port=80,
            protocol="TCP",
        )
        results = simulate_traffic(policies, [flow])
        assert len(results) == 1
        assert results[0].verdict in (TrafficVerdict.ALLOW, TrafficVerdict.DENY, TrafficVerdict.UNKNOWN)

    def test_simulate_no_policies(self):
        flow = TrafficFlow(
            source_pod="a",
            source_namespace="default",
            source_labels={},
            dest_pod="b",
            dest_namespace="default",
            dest_labels={},
            port=80,
        )
        results = simulate_traffic([], [flow])
        assert len(results) == 1

    def test_simulate_multiple_flows(self, good_manifests):
        policies, _ = parse_manifests(good_manifests)
        flows = [
            TrafficFlow("a", "default", {}, "b", "default", {}, 80, "TCP"),
            TrafficFlow("c", "default", {}, "d", "default", {}, 443, "TCP"),
        ]
        results = simulate_traffic(policies, flows)
        assert len(results) == 2

    def test_empty_flows(self, good_manifests):
        policies, _ = parse_manifests(good_manifests)
        results = simulate_traffic(policies, [])
        assert results == []
