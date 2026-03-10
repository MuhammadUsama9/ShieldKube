from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from .scanner import K8sScanner
import os

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

@app.get("/health")
async def health_check():
    return {"status": "healthy", "mock_mode": scanner.mock_mode}

@app.get("/api/pods")
async def get_pods():
    return scanner.scan_pods()

@app.get("/api/heatmap")
async def get_heatmap():
    return scanner.scan_heatmap()

@app.get("/api/rbac")
async def get_rbac():
    return scanner.scan_rbac()

@app.get("/api/network-policies")
async def get_network_policies():
    return scanner.scan_network_policies()

@app.get("/api/summary")
async def get_summary():
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

@app.get("/api/inventory")
async def get_inventory():
    return scanner.scan_inventory()

@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    return scanner.scan_vulnerabilities()

@app.get("/api/radar")
async def get_radar():
    return scanner.scan_radar_data()

@app.get("/api/trends")
async def get_trends():
    return scanner.scan_trends()

@app.get("/api/logs")
async def get_logs():
    return scanner.get_logs()

@app.get("/api/compliance")
async def get_compliance():
    return scanner.scan_compliance()

@app.get("/api/metrics")
async def get_metrics():
    return scanner.scan_metrics()

@app.post("/api/remediate")
async def remediate(data: dict):
    return scanner.remediate_resource(
        kind=data.get("kind"),
        name=data.get("name"),
        namespace=data.get("namespace"),
        patch_data=data.get("patch")
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
