"""Core data models for kube-netpol."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PolicyType(Enum):
    """NetworkPolicy types."""
    INGRESS = "Ingress"
    EGRESS = "Egress"
    BOTH = "Ingress+Egress"


class TrafficVerdict(Enum):
    """Traffic flow verdict."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

VERDICT_COLORS = {
    TrafficVerdict.ALLOW: "green",
    TrafficVerdict.DENY: "red",
    TrafficVerdict.UNKNOWN: "yellow",
}

VERDICT_ICONS = {
    TrafficVerdict.ALLOW: "✅",
    TrafficVerdict.DENY: "🚫",
    TrafficVerdict.UNKNOWN: "❓",
}


@dataclass
class Issue:
    """A validation issue found in a NetworkPolicy."""
    rule_id: str
    severity: Severity
    message: str
    file_path: str
    policy_name: str = ""
    line: Optional[int] = None
    suggestion: Optional[str] = None
    doc_url: Optional[str] = None


@dataclass
class PolicyRule:
    """A single ingress or egress rule within a NetworkPolicy."""
    direction: str  # "ingress" or "egress"
    ports: list = field(default_factory=list)
    from_selectors: list = field(default_factory=list)
    to_selectors: list = field(default_factory=list)
    ip_blocks: list = field(default_factory=list)


@dataclass
class NetworkPolicy:
    """Parsed representation of a Kubernetes NetworkPolicy."""
    name: str
    namespace: str = "default"
    pod_selector: dict = field(default_factory=dict)
    policy_types: list = field(default_factory=list)
    ingress_rules: list = field(default_factory=list)
    egress_rules: list = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)
    file_path: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class TrafficFlow:
    """Represents a single traffic flow for simulation."""
    source_pod: str
    source_namespace: str
    source_labels: dict
    dest_pod: str
    dest_namespace: str
    dest_labels: dict
    port: Optional[int] = None
    protocol: str = "TCP"
    verdict: TrafficVerdict = TrafficVerdict.UNKNOWN
    matched_policy: str = ""
    matched_rule: str = ""


@dataclass
class PolicyConnection:
    """A connection edge for visualization."""
    source: str
    destination: str
    ports: list = field(default_factory=list)
    direction: str = "ingress"
    policy_name: str = ""


@dataclass
class AnalysisReport:
    """Full analysis report."""
    scan_path: str
    total_policies: int = 0
    policies: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    connections: list = field(default_factory=list)
    traffic_flows: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    score: float = 100.0
    grade: str = "A+"

    @property
    def critical_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    @property
    def info_count(self):
        return sum(1 for i in self.issues if i.severity == Severity.INFO)

    def calculate_score(self):
        """Calculate security score based on issues."""
        weights = {Severity.CRITICAL: 20, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}
        total_deductions = sum(weights[i.severity] for i in self.issues)
        max_deduction = max(self.total_policies * 15, 50)
        self.score = max(0, round(100 - (total_deductions / max(max_deduction, 1)) * 100, 1))

        if self.score >= 95:
            self.grade = "A+"
        elif self.score >= 90:
            self.grade = "A"
        elif self.score >= 85:
            self.grade = "A-"
        elif self.score >= 80:
            self.grade = "B+"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 70:
            self.grade = "B-"
        elif self.score >= 65:
            self.grade = "C+"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 55:
            self.grade = "C-"
        elif self.score >= 50:
            self.grade = "D"
        elif self.score >= 40:
            self.grade = "D-"
        else:
            self.grade = "F"
