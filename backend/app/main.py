import os
import time
import secrets
from fastapi import FastAPI, Query, Body, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from .scanner import K8sScanner
from .database import db

app = FastAPI(title="Kubernetes Security Risk Dashboard API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, this should be restricted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication configuration
AGENT_API_KEY = os.getenv("SHIELDKUBE_API_KEY", "shieldkube-default-key-2024")

# Initialize scanner
# Use MOCK_MODE environment variable to force mock data
mock_mode_env = os.getenv("MOCK_MODE", "true").lower() == "true"
scanner = K8sScanner(mock_mode=mock_mode_env)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "mock_mode": scanner.mock_mode}

@app.get("/api/dashboard/bootstrap/{cluster_id}")
async def bootstrap_dashboard(cluster_id: str = "local"):
    print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP: Request for {cluster_id}")
    try:
        # Consolidate most critical data for initial load
        clusters = await get_clusters()
        print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP: Clusters fetched")
        summary = await get_summary(cluster_id)
        print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP: Summary fetched")
        pods = await get_pods(cluster_id)
        print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP: Pods fetched")
        vulnerabilities = await get_vulnerabilities(cluster_id)
        print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP: Vulns fetched")
        radar = await get_radar(cluster_id)
        print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP: Radar fetched")
        
        return {
            "clusters": clusters,
            "summary": summary,
            "pods": pods,
            "vulnerabilities": vulnerabilities,
            "radar": radar
        }
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] BOOTSTRAP ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/clusters")
async def get_clusters():
    clusters = db.get_clusters()
    # Format for frontend expectations if needed
    for c in clusters:
        # Determine status based on last_sync
        c["status"] = "Active" if c["last_sync"] and (time.time() - c["last_sync"]) < 600 else "Offline"
        c["is_local"] = bool(c["is_local"])
    return clusters

@app.delete("/api/clusters/{cluster_id}")
async def delete_cluster(cluster_id: str):
    if cluster_id == "local":
        return {"status": "error", "msg": "Cannot remove the local control plane cluster."}
    db.delete_cluster(cluster_id)
    return {"status": "success"}

@app.post("/api/agent/v1/sync/{cluster_id}")
async def sync_agent_data(cluster_id: str, request: Request, payload: dict = Body(...)):
    # 1. Authenticate Agent
    api_key = request.headers.get("X-API-KEY")
    if api_key != AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Update Cluster Registry
    db.update_cluster(cluster_id, payload.get("cluster_name", f"Cluster {cluster_id}"))

    # 3. Store Telemetry Data (Shredded for query efficiency)
    data_types = ["pods", "heatmap", "rbac", "network_policies", "inventory", 
                  "vulnerabilities", "radar", "trends", "compliance", "metrics", 
                  "events", "secrets", "summary", "logs"]
    
    for dt in data_types:
        if dt in payload:
            db.save_telemetry(cluster_id, dt, payload[dt])
    
    print(f"[{time.strftime('%H:%M:%S')}] Enterprise Sync: Received telemetry from {cluster_id}")
    return {"status": "success", "timestamp": time.time()}

@app.get("/api/agent/agent.py", response_class=PlainTextResponse)
async def get_agent_py():
    with open("agent.py", "r") as f:
        return f.read()

@app.get("/api/agent/app/scanner.py", response_class=PlainTextResponse)
async def get_scanner_py():
    with open("app/scanner.py", "r") as f:
        return f.read()

@app.get("/api/agent/install", response_class=PlainTextResponse)
async def get_agent_install_yaml(request: Request, cluster_id: str = "remote-1", cluster_name: str = "Remote Cluster", base_url: str = None):
    # Robust URL detection
    if base_url:
        # Fix possible slash collapsing (e.g. http:/ becoming http://)
        if base_url.startswith("http:/") and not base_url.startswith("http://"):
            base_url = base_url.replace("http:/", "http://", 1)
        elif base_url.startswith("https:/") and not base_url.startswith("https://"):
            base_url = base_url.replace("https:/", "https://", 1)
        
        # Strip trailing slash
        base_url = base_url.rstrip("/")
    else:
        # Fallback to Host header
        base_url = f"{request.url.scheme}://{request.headers.get('host')}"
        if request.headers.get("x-forwarded-proto") == "https":
            base_url = f"https://{request.headers.get('host')}"
    
    print(f"[{time.strftime('%H:%M:%S')}] Generating install YAML for {cluster_id}. Agent callback: {base_url}")
        
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
  resources: ["pods", "nodes", "services", "configmaps", "secrets", "namespaces", "events", "deployments", "replicasets", "networkpolicies", "clusterroles", "resourcequotas", "limitranges", "poddisruptionbudgets", "jobs", "cronjobs"]
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
      containers:
      - name: agent
        image: mcr.microsoft.com/mirror/docker/library/python:3.11-slim
        command: ["/bin/sh", "-c"]
        args:
        - "apt-get update && apt-get install -y wget && pip install requests kubernetes schedule && mkdir -p app && wget -q {base_url}/api/agent/agent.py -O agent.py && wget -q {base_url}/api/agent/app/scanner.py -O app/scanner.py && touch app/__init__.py && python -u agent.py"
        env:
        - name: SHIELDKUBE_URL
          value: "{base_url}"
        - name: CLUSTER_ID
          value: "{cluster_id}"
        - name: CLUSTER_NAME
          value: "{cluster_name}"
        - name: SHIELDKUBE_API_KEY
          value: "{AGENT_API_KEY}"
        - name: SYNC_INTERVAL_SEC
          value: "60"
        - name: MOCK_MODE
          value: "false"
        resources:
          limits:
            cpu: "250m"
            memory: "256Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
"""
    return yaml_script.strip()

@app.get("/api/pods")
async def get_pods(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_pods()
    return db.get_telemetry(cluster_id, "pods", [])

@app.get("/api/heatmap")
async def get_heatmap(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_heatmap()
    return db.get_telemetry(cluster_id, "heatmap", [])

@app.get("/api/rbac")
async def get_rbac(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_rbac()
    return db.get_telemetry(cluster_id, "rbac", [])

@app.get("/api/network-policies")
async def get_network_policies(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_network_policies()
    return db.get_telemetry(cluster_id, "network_policies", [])

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
    return db.get_telemetry(cluster_id, "summary", {
        "total_pods": 0, "total_policies": 0, "total_rbac": 0,
        "total_vulnerabilities": 0, "total_risks": 0, "security_score": 0,
        "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    })

@app.get("/api/inventory")
async def get_inventory(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_inventory()
    return db.get_telemetry(cluster_id, "inventory", [])

@app.get("/api/vulnerabilities")
async def get_vulnerabilities(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_vulnerabilities()
    return db.get_telemetry(cluster_id, "vulnerabilities", {})

@app.get("/api/radar")
async def get_radar(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_radar_data()
    return db.get_telemetry(cluster_id, "radar", [])

@app.get("/api/trends")
async def get_trends(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_trends()
    return db.get_telemetry(cluster_id, "trends", [])

@app.get("/api/logs")
async def get_logs(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.get_logs()
    return db.get_telemetry(cluster_id, "logs", [])

@app.get("/api/compliance")
async def get_compliance(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_compliance()
    return db.get_telemetry(cluster_id, "compliance", [])

@app.get("/api/metrics")
async def get_metrics(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_metrics()
    return db.get_telemetry(cluster_id, "metrics", {"pods": [], "nodes": []})

@app.get("/api/events")
async def get_events(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_events()
    return db.get_telemetry(cluster_id, "events", [])

@app.get("/api/secrets")
async def get_secrets(cluster_id: str = "local"):
    if cluster_id == "local": return scanner.scan_secrets()
    return db.get_telemetry(cluster_id, "secrets", [])

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
