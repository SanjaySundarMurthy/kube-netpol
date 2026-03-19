"""NetworkPolicy generator — create policies from templates and workload analysis."""
import yaml

from kube_netpol.models import NetworkPolicy


# Template library for common patterns
TEMPLATES = {
    "default-deny-ingress": {
        "name": "Default Deny Ingress",
        "description": "Block all inbound traffic to pods in a namespace",
        "manifest": lambda ns: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-ingress",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "kube-netpol/template": "default-deny-ingress",
                },
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress"],
            },
        },
    },
    "default-deny-egress": {
        "name": "Default Deny Egress",
        "description": "Block all outbound traffic from pods in a namespace",
        "manifest": lambda ns: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-egress",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "kube-netpol/template": "default-deny-egress",
                },
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
            },
        },
    },
    "default-deny-all": {
        "name": "Default Deny All",
        "description": "Block all inbound AND outbound traffic (zero-trust baseline)",
        "manifest": lambda ns: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-all",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "kube-netpol/template": "default-deny-all",
                },
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
            },
        },
    },
    "allow-dns": {
        "name": "Allow DNS Egress",
        "description": "Allow pods to resolve DNS via kube-dns/CoreDNS",
        "manifest": lambda ns: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-dns-egress",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "kube-netpol/template": "allow-dns",
                },
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system",
                                    },
                                },
                            },
                        ],
                        "ports": [
                            {"port": 53, "protocol": "TCP"},
                            {"port": 53, "protocol": "UDP"},
                        ],
                    },
                ],
            },
        },
    },
    "allow-internet-egress": {
        "name": "Allow Internet Egress",
        "description": "Allow outbound traffic to external IPs (excluding cloud metadata)",
        "manifest": lambda ns: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-internet-egress",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "kube-netpol/template": "allow-internet-egress",
                },
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [
                    {
                        "to": [
                            {
                                "ipBlock": {
                                    "cidr": "0.0.0.0/0",
                                    "except": [
                                        "10.0.0.0/8",
                                        "172.16.0.0/12",
                                        "192.168.0.0/16",
                                        "169.254.169.254/32",
                                    ],
                                },
                            },
                        ],
                        "ports": [
                            {"port": 443, "protocol": "TCP"},
                            {"port": 80, "protocol": "TCP"},
                        ],
                    },
                ],
            },
        },
    },
    "web-app": {
        "name": "Web Application",
        "description": "Allow HTTP/HTTPS ingress and DNS+HTTPS egress for a typical web app",
        "manifest": lambda ns, app="my-app": {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{app}-web-policy",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "app.kubernetes.io/name": app,
                    "kube-netpol/template": "web-app",
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {"app": app},
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "ports": [
                            {"port": 80, "protocol": "TCP"},
                            {"port": 443, "protocol": "TCP"},
                        ],
                    },
                ],
                "egress": [
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system",
                                    },
                                },
                            },
                        ],
                        "ports": [
                            {"port": 53, "protocol": "TCP"},
                            {"port": 53, "protocol": "UDP"},
                        ],
                    },
                ],
            },
        },
    },
    "backend-api": {
        "name": "Backend API",
        "description": "Allow ingress only from frontend, allow DB egress + DNS",
        "manifest": lambda ns, app="api", frontend="frontend", db_port=5432: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{app}-backend-policy",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "app.kubernetes.io/name": app,
                    "kube-netpol/template": "backend-api",
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {"app": app},
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {"podSelector": {"matchLabels": {"app": frontend}}},
                        ],
                        "ports": [
                            {"port": 8080, "protocol": "TCP"},
                        ],
                    },
                ],
                "egress": [
                    {
                        "to": [
                            {"podSelector": {"matchLabels": {"app": "database"}}},
                        ],
                        "ports": [
                            {"port": db_port, "protocol": "TCP"},
                        ],
                    },
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system",
                                    },
                                },
                            },
                        ],
                        "ports": [
                            {"port": 53, "protocol": "TCP"},
                            {"port": 53, "protocol": "UDP"},
                        ],
                    },
                ],
            },
        },
    },
    "database": {
        "name": "Database",
        "description": "Allow ingress only from backend pods on the DB port",
        "manifest": lambda ns, app="database", backend="api", port=5432: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{app}-db-policy",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "app.kubernetes.io/name": app,
                    "kube-netpol/template": "database",
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {"app": app},
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {"podSelector": {"matchLabels": {"app": backend}}},
                        ],
                        "ports": [
                            {"port": port, "protocol": "TCP"},
                        ],
                    },
                ],
                "egress": [
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "kube-system",
                                    },
                                },
                            },
                        ],
                        "ports": [
                            {"port": 53, "protocol": "TCP"},
                            {"port": 53, "protocol": "UDP"},
                        ],
                    },
                ],
            },
        },
    },
    "monitoring": {
        "name": "Monitoring (Prometheus)",
        "description": "Allow Prometheus scraping on metrics port from monitoring namespace",
        "manifest": lambda ns, app="my-app", metrics_port=9090: {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{app}-allow-monitoring",
                "namespace": ns,
                "labels": {
                    "app.kubernetes.io/managed-by": "kube-netpol",
                    "kube-netpol/template": "monitoring",
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {"app": app},
                },
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "monitoring",
                                    },
                                },
                                "podSelector": {
                                    "matchLabels": {"app": "prometheus"},
                                },
                            },
                        ],
                        "ports": [
                            {"port": metrics_port, "protocol": "TCP"},
                        ],
                    },
                ],
            },
        },
    },
    "microservices-suite": {
        "name": "Full Microservices Suite",
        "description": "Complete zero-trust policies for a 3-tier app (frontend → backend → database)",
        "manifest": lambda ns: None,  # Special: generates multiple policies
    },
}


def generate_policy(template_name: str, namespace: str = "default", **kwargs) -> str:
    """Generate a NetworkPolicy YAML from a template."""
    if template_name not in TEMPLATES:
        raise ValueError(f"Unknown template: '{template_name}'. Available: {', '.join(TEMPLATES.keys())}")

    template = TEMPLATES[template_name]

    if template_name == "microservices-suite":
        return _generate_microservices_suite(namespace, **kwargs)

    manifest_fn = template["manifest"]
    try:
        manifest = manifest_fn(namespace, **kwargs)
    except TypeError:
        manifest = manifest_fn(namespace)

    return yaml.dump(manifest, default_flow_style=False, sort_keys=False)


def _generate_microservices_suite(namespace: str, **kwargs) -> str:
    """Generate a complete set of policies for a microservices architecture."""
    app_name = kwargs.get("app", "myapp")

    policies = []

    # 1. Default deny all
    policies.append(TEMPLATES["default-deny-all"]["manifest"](namespace))

    # 2. Allow DNS
    policies.append(TEMPLATES["allow-dns"]["manifest"](namespace))

    # 3. Frontend policy
    frontend_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{app_name}-frontend",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "kube-netpol",
                "app.kubernetes.io/name": f"{app_name}-frontend",
                "app.kubernetes.io/part-of": app_name,
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": f"{app_name}-frontend"}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {
                    "ports": [
                        {"port": 80, "protocol": "TCP"},
                        {"port": 443, "protocol": "TCP"},
                    ],
                },
            ],
            "egress": [
                {
                    "to": [
                        {"podSelector": {"matchLabels": {"app": f"{app_name}-backend"}}},
                    ],
                    "ports": [
                        {"port": 8080, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [
                        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}},
                    ],
                    "ports": [
                        {"port": 53, "protocol": "TCP"},
                        {"port": 53, "protocol": "UDP"},
                    ],
                },
            ],
        },
    }
    policies.append(frontend_policy)

    # 4. Backend policy
    backend_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{app_name}-backend",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "kube-netpol",
                "app.kubernetes.io/name": f"{app_name}-backend",
                "app.kubernetes.io/part-of": app_name,
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": f"{app_name}-backend"}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {
                    "from": [
                        {"podSelector": {"matchLabels": {"app": f"{app_name}-frontend"}}},
                    ],
                    "ports": [
                        {"port": 8080, "protocol": "TCP"},
                    ],
                },
            ],
            "egress": [
                {
                    "to": [
                        {"podSelector": {"matchLabels": {"app": f"{app_name}-database"}}},
                    ],
                    "ports": [
                        {"port": 5432, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [
                        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}},
                    ],
                    "ports": [
                        {"port": 53, "protocol": "TCP"},
                        {"port": 53, "protocol": "UDP"},
                    ],
                },
            ],
        },
    }
    policies.append(backend_policy)

    # 5. Database policy
    db_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{app_name}-database",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "kube-netpol",
                "app.kubernetes.io/name": f"{app_name}-database",
                "app.kubernetes.io/part-of": app_name,
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": f"{app_name}-database"}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {
                    "from": [
                        {"podSelector": {"matchLabels": {"app": f"{app_name}-backend"}}},
                    ],
                    "ports": [
                        {"port": 5432, "protocol": "TCP"},
                    ],
                },
            ],
            "egress": [
                {
                    "to": [
                        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}},
                    ],
                    "ports": [
                        {"port": 53, "protocol": "TCP"},
                        {"port": 53, "protocol": "UDP"},
                    ],
                },
            ],
        },
    }
    policies.append(db_policy)

    # Combine all policies into multi-doc YAML
    docs = []
    for p in policies:
        docs.append(yaml.dump(p, default_flow_style=False, sort_keys=False))

    return "---\n".join(docs)


def list_templates() -> list:
    """Return list of available templates with descriptions."""
    return [
        {"name": name, "description": t["description"], "display_name": t["name"]}
        for name, t in TEMPLATES.items()
    ]
