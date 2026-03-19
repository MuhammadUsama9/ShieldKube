from fastapi import FastAPI, Query, Body, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from .scanner import K8sScanner
import os
import time

app = FastAPI(title="Kubernetes Security Risk Dashboard API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, this should be restricted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scanner
# Use MOCK_MODE environment variable to force mock data
mock_mode_env = os.getenv("MOCK_MODE", "true").lower() == "true"
scanner = K8sScanner(mock_mode=mock_mode_env)

# In-memory store for agent data
agent_data = {}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "mock_mode": scanner.mock_mode}

@app.get("/api/clusters")
async def get_clusters():
    clusters = [
        {"id": "local", "name": "Local Cluster", "status": "Active", "is_local": True}
    ]
    for cid, data in agent_data.items():
        clusters.append({
            "id": cid, 
            "name": data.get("name", f"Remote Cluster ({cid[:6]})"), 
            "status": "Active" if (time.time() - data.get("last_sync", 0)) < 600 else "Offline",
            "last_sync": data.get("last_sync"),
            "is_local": False
        })
    return clusters

@app.delete("/api/clusters/{cluster_id}")
async def delete_cluster(cluster_id: str):
    if cluster_id == "local":
        return {"status": "error", "msg": "Cannot remove the local control plane cluster."}
    if cluster_id in agent_data:
        del agent_data[cluster_id]
        return {"status": "success"}
    return {"status": "error", "msg": "Cluster not found"}

@app.post("/api/agent/v1/sync/{cluster_id}")
async def sync_agent_data(cluster_id: str, payload: dict = Body(...)):
    if cluster_id not in agent_data:
        agent_data[cluster_id] = {"name": payload.get("cluster_name", f"Cluster {cluster_id}")}
    
    agent_data[cluster_id].update(payload)
    agent_data[cluster_id]["last_sync"] = time.time()
    return {"status": "success"}

@app.get("/api/agent/install", response_class=PlainTextResponse)
async def get_agent_install_yaml(request: Request, cluster_id: str = "remote-1", cluster_name: str = "Remote Cluster"):
    base_url = f"{request.url.scheme}://{request.headers.get('host')}"
    if request.headers.get("x-forwarded-proto") == "https":
        base_url = f"https://{request.headers.get('host')}"
        
    yaml_script = f"""apiVersion: v1
kind: Namespace
metadata:
  name: shieldkube-agent
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: shieldkube-agent-sa
  namespace: shieldkube-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: shieldkube-agent-role
rules:
- apiGroups: ["", "apps", "networking.k8s.io", "rbac.authorization.k8s.io", "policy", "metrics.k8s.io", "batch"]
  resources: ["pods", "nodes", "services", "configmaps", "secrets", "namespaces", "events", "deployments", "replicasets", "networkpolicies", "clusterroles", "resourcequotas", "limitranges", "poddisruptionbudgets", "jobs", "cronjobs", "daemonsets", "statefulsets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: shieldkube-agent-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: shieldkube-agent-role
subjects:
- kind: ServiceAccount
  name: shieldkube-agent-sa
  namespace: shieldkube-agent
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shieldkube-agent
  namespace: shieldkube-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: shieldkube-agent
  template:
    metadata:
      labels:
        app: shieldkube-agent
    spec:
      serviceAccountName: shieldkube-agent-sa
      hostPID: true
      containers:
      - name: agent
        image: public.ecr.aws/docker/library/golang:1.21-alpine
        command: ["/bin/sh", "-c"]
        args:
        - >
          apk add --no-cache git curl tar bash jq &&
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.49.1 &&
          curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.17/kube-bench_0.6.17_linux_amd64.tar.gz -o kube-bench.tar.gz &&
          tar -xvf kube-bench.tar.gz && mv kube-bench /usr/local/bin/ && rm kube-bench.tar.gz &&
          git clone https://github.com/MuhammadUsama9/ShieldKube.git /shieldkube &&
          cd /shieldkube/backend-go &&
          go mod init shieldkube-go &&
          go get k8s.io/client-go@v0.29.2 k8s.io/api@v0.29.2 k8s.io/apimachinery@v0.29.2 &&
          go mod tidy &&
          go run main.go
        env:
        - name: SHIELDKUBE_URL
          value: "{base_url}"
        - name: CLUSTER_ID
          value: "{cluster_id}"
        - name: CLUSTER_NAME
          value: "{cluster_name}"
        - name: SYNC_INTERVAL_SEC
          value: "60"
        volumeMounts:
        - name: var-lib-etcd
          mountPath: /var/lib/etcd
          readOnly: true
        - name: var-lib-kubelet
          mountPath: /var/lib/kubelet
          readOnly: true
        - name: var-lib-kube-scheduler
          mountPath: /var/lib/kube-scheduler
          readOnly: true
        - name: var-lib-kube-controller-manager
          mountPath: /var/lib/kube-controller-manager
          readOnly: true
        - name: etc-systemd
          mountPath: /etc/systemd
          readOnly: true
        - name: lib-systemd
          mountPath: /lib/systemd
          readOnly: true
        - name: srv-kubernetes
          mountPath: /srv/kubernetes
          readOnly: true
        - name: etc-kubernetes
          mountPath: /etc/kubernetes
          readOnly: true
        - name: usr-bin
          mountPath: /usr/local/mount-from-host/bin
          readOnly: true
        - name: etc-cni-netd
          mountPath: /etc/cni/net.d/
          readOnly: true
        - name: opt-cni-bin
          mountPath: /opt/cni/bin/
          readOnly: true
      volumes:
      - name: var-lib-etcd
        hostPath:
          path: "/var/lib/etcd"
      - name: var-lib-kubelet
        hostPath:
          path: "/var/lib/kubelet"
      - name: var-lib-kube-scheduler
        hostPath:
          path: "/var/lib/kube-scheduler"
      - name: var-lib-kube-controller-manager
        hostPath:
          path: "/var/lib/kube-controller-manager"
      - name: etc-systemd
        hostPath:
          path: "/etc/systemd"
      - name: lib-systemd
        hostPath:
          path: "/lib/systemd"
      - name: srv-kubernetes
        hostPath:
          path: "/srv/kubernetes"
      - name: etc-kubernetes
        hostPath:
          path: "/etc/kubernetes"
      - name: usr-bin
        hostPath:
          path: "/usr/bin"
      - name: etc-cni-netd
        hostPath:
          path: "/etc/cni/net.d/"
      - name: opt-cni-bin
        hostPath:
          path: "/opt/cni/bin/"
"""
    return yaml_script.strip()

@app.get("/api/pods")
async def get_pods(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_pods()
    return agent_data.get(cluster_id, {}).get("pods", [])

@app.get("/api/heatmap")
async def get_heatmap(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_heatmap()
    return agent_data.get(cluster_id, {}).get("heatmap", [])

@app.get("/api/rbac")
async def get_rbac(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_rbac()
    return agent_data.get(cluster_id, {}).get("rbac", [])

@app.get("/api/network-policies")
async def get_network_policies(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_network_policies()
    return agent_data.get(cluster_id, {}).get("network_policies", [])

@app.get("/api/summary")
async def get_summary(cluster_id: str = "local"):
    if cluster_id == "local":
        pods = scanner.scan_pods()
        policies = scanner.scan_network_policies()
        rbac = scanner.scan_rbac()
        vulnerabilities = scanner.scan_vulnerabilities()
        
        severity_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        total_risks = 0
        
        for item in pods + policies + rbac:
            severity_dist[item["severity"]] += 1
            total_risks += len(item.get("risks", []))
        
        total_vulns = sum(len(vlist) for vlist in vulnerabilities.values())
            
        return {
            "total_pods": len(pods),
            "total_policies": len(policies),
            "total_rbac": len(rbac),
            "total_vulnerabilities": total_vulns,
            "total_risks": total_risks,
            "security_score": scanner.calculate_security_score(pods, policies, rbac, vulnerabilities),
            "severity_distribution": severity_dist
        }
    return agent_data.get(cluster_id, {}).get("summary", {
        "total_pods": 0, "total_policies": 0, "total_rbac": 0,
        "total_vulnerabilities": 0, "total_risks": 0, "security_score": 0,
        "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    })

@app.get("/api/inventory")
async def get_inventory(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_inventory()
    return agent_data.get(cluster_id, {}).get("inventory", [])

@app.get("/api/vulnerabilities")
async def get_vulnerabilities(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_vulnerabilities()
    return agent_data.get(cluster_id, {}).get("vulnerabilities", {})

@app.get("/api/radar")
async def get_radar(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_radar_data()
    return agent_data.get(cluster_id, {}).get("radar", [])

@app.get("/api/trends")
async def get_trends(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_trends()
    return agent_data.get(cluster_id, {}).get("trends", [])

@app.get("/api/logs")
async def get_logs(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.get_logs()
    return agent_data.get(cluster_id, {}).get("logs", [])

@app.get("/api/compliance")
async def get_compliance(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_compliance()
    return agent_data.get(cluster_id, {}).get("compliance", [])

@app.get("/api/metrics")
async def get_metrics(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_metrics()
    return agent_data.get(cluster_id, {}).get("metrics", {"pods": [], "nodes": []})

@app.get("/api/events")
async def get_events(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_events()
    return agent_data.get(cluster_id, {}).get("events", [])

@app.get("/api/secrets")
async def get_secrets(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_secrets()
    return agent_data.get(cluster_id, {}).get("secrets", [])

@app.post("/api/remediate")
async def remediate(data: dict):
    cluster_id = data.get("cluster_id", "local")
    if cluster_id == "local":
        return scanner.remediate_resource(
            kind=data.get("kind"),
            name=data.get("name"),
            namespace=data.get("namespace"),
            patch_data=data.get("patch")
        )
    return {"status": "error", "msg": "Remediation on remote agent clusters not yet supported"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
