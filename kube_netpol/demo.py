"""Demo mode — creates realistic K8s manifests with NetworkPolicy issues."""
import os
import tempfile


def create_demo_manifests() -> str:
    """Create demo Kubernetes manifests with intentional NetworkPolicy issues."""
    demo_dir = tempfile.mkdtemp(prefix="kube-netpol-demo-")

    # 1. A decent default-deny ingress (but missing egress deny)
    _write(demo_dir, "01-default-deny.yaml", """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: ecommerce
spec:
  podSelector: {}
  policyTypes:
  - Ingress
""")

    # 2. Frontend policy — allows from all (too permissive)
    _write(demo_dir, "02-frontend-policy.yaml", """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-allow
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - ports:
    - port: 80
      protocol: TCP
    - port: 443
      protocol: TCP
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend-api
    ports:
    - port: 8080
      protocol: TCP
""")

    # 3. Backend API — allows from ALL namespaces (dangerous)
    _write(demo_dir, "03-backend-policy.yaml", """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-api-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      app: backend-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector: {}
      podSelector: {}
    ports:
    - port: 8080
      protocol: TCP
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - port: 5432
      protocol: TCP
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - port: 443
      protocol: TCP
""")

    # 4. Database — exposes dangerous ports, overly broad
    _write(demo_dir, "04-database-policy.yaml", """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: postgres-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      app: postgres
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend-api
    ports:
    - port: 5432
      protocol: TCP
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - port: 22
      protocol: TCP
""")

    # 5. Redis — allows all ports (bad!)
    _write(demo_dir, "05-redis-policy.yaml", """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: redis-cache-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      app: redis
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend-api
""")

    # 6. Monitoring — allows from external without restriction
    _write(demo_dir, "06-monitoring-policy.yaml", """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: monitoring-policy
  namespace: ecommerce
spec:
  podSelector:
    matchLabels:
      app: prometheus
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - ports:
    - port: 9090
      protocol: TCP
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
    ports:
    - port: 9090
      protocol: TCP
    - port: 443
      protocol: TCP
""")

    # 7. Workloads (Deployments) for coverage analysis
    _write(demo_dir, "07-workloads.yaml", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: ecommerce
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: nginx:1.25
        ports:
        - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-api
  namespace: ecommerce
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend-api
  template:
    metadata:
      labels:
        app: backend-api
    spec:
      containers:
      - name: api
        image: myapp/api:2.1.0
        ports:
        - containerPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: ecommerce
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        ports:
        - containerPort: 5432
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: ecommerce
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7
        ports:
        - containerPort: 6379
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: ecommerce
spec:
  replicas: 2
  selector:
    matchLabels:
      app: worker
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
      - name: worker
        image: myapp/worker:2.1.0
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: ecommerce
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:v2.48.0
        ports:
        - containerPort: 9090
""")

    return demo_dir


def _write(directory: str, filename: str, content: str):
    """Write a file."""
    with open(os.path.join(directory, filename), "w", encoding="utf-8") as f:
        f.write(content.lstrip("\n"))
