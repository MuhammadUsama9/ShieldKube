import os
import time
import requests
import schedule
from app.scanner import K8sScanner

# Configuration from Environment Variables
SHIELDKUBE_URL = os.getenv("SHIELDKUBE_URL", "http://host.minikube.internal:8000")
# Fix possible slash collapsing
if SHIELDKUBE_URL.startswith("http:/") and not SHIELDKUBE_URL.startswith("http://"):
    SHIELDKUBE_URL = SHIELDKUBE_URL.replace("http:/", "http://", 1)
elif SHIELDKUBE_URL.startswith("https:/") and not SHIELDKUBE_URL.startswith("https://"):
    SHIELDKUBE_URL = SHIELDKUBE_URL.replace("https:/", "https://", 1)
SHIELDKUBE_URL = SHIELDKUBE_URL.rstrip("/")

CLUSTER_ID = os.getenv("CLUSTER_ID", "agent-cluster-1")
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "Remote K8s Cluster")
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL_SEC", "60"))
MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() == "true"
# Enterprise Auth
AGENT_API_KEY = os.getenv("SHIELDKUBE_API_KEY", "shieldkube-default-key-2024")

def sync_with_retry(url, payload, max_retries=5):
    """Sync data to backend with exponential backoff retry logic."""
    headers = {"X-API-KEY": AGENT_API_KEY}
    backoff = 2
    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                print(f"[{time.strftime('%H:%M:%S')}] Sync Successful (Attempt {attempt + 1})")
                return True
            elif response.status_code == 401:
                print(f"[{time.strftime('%H:%M:%S')}] Auth Failed: Invalid API Key")
                return False
            else:
                print(f"[{time.strftime('%H:%M:%S')}] Sync Failed (Status {response.status_code})")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Connection Error: {e}")
        
        if attempt < max_retries - 1:
            print(f"Retrying in {backoff} seconds...")
            time.sleep(backoff)
            backoff *= 2
    return False

def run_scan_and_sync():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting cluster scan for {CLUSTER_ID}...")
    
    try:
        scanner = K8sScanner(mock_mode=MOCK_MODE)
        
        # Collect all data
        pods = scanner.scan_pods()
        policies = scanner.scan_network_policies()
        rbac = scanner.scan_rbac()
        vulnerabilities = scanner.scan_vulnerabilities()
        
        # Calculate summary natively
        severity_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        total_risks = 0
        
        for item in pods + policies + rbac:
            severity_dist[item.get("severity", "Low")] += 1
            total_risks += len(item.get("risks", []))
            
        total_vulns = sum(len(vlist) for vlist in vulnerabilities.values())
        
        summary = {
            "total_pods": len(pods),
            "total_policies": len(policies),
            "total_rbac": len(rbac),
            "total_vulnerabilities": total_vulns,
            "total_risks": total_risks,
            "security_score": scanner.calculate_security_score(pods, policies, rbac, vulnerabilities),
            "severity_distribution": severity_dist
        }
        
        payload = {
            "cluster_id": CLUSTER_ID,
            "cluster_name": CLUSTER_NAME,
            "pods": pods,
            "heatmap": scanner.scan_heatmap(),
            "rbac": rbac,
            "network_policies": policies,
            "inventory": scanner.scan_inventory(),
            "vulnerabilities": vulnerabilities,
            "radar": scanner.scan_radar_data(),
            "trends": scanner.scan_trends(),
            "compliance": scanner.scan_compliance(),
            "metrics": scanner.scan_metrics(),
            "events": scanner.scan_events(),
            "secrets": scanner.scan_secrets(),
            "summary": summary,
            "logs": scanner.get_logs()
        }

        # Push to API with enterprise retry logic
        sync_url = f"{SHIELDKUBE_URL}/api/agent/v1/sync/{CLUSTER_ID}"
        print(f"Pushing {len(str(payload))} bytes of payload to {sync_url}...")
        
        success = sync_with_retry(sync_url, payload)
        
        if success:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Successfully synced to main backend.")
        else:
            print(f"Failed to sync after multiple attempts.")
            
    except Exception as e:
        sync_url = f"{SHIELDKUBE_URL}/api/agent/v1/sync/{CLUSTER_ID}"
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] CRITICAL: Scan/Sync failed.")
        print(f"Error: {e}")
        print(f"Verify that the backend is reachable at: {sync_url}")

if __name__ == "__main__":
    print(f"ShieldKube Agent starting up...")
    print(f"Target Backend: {SHIELDKUBE_URL}")
    print(f"Cluster ID: {CLUSTER_ID} | Name: {CLUSTER_NAME}")
    print(f"Sync Interval: {SYNC_INTERVAL} seconds")
    
    # Run once immediately on startup
    run_scan_and_sync()
    
    # Schedule recurring scans
    schedule.every(SYNC_INTERVAL).seconds.do(run_scan_and_sync)
    
    while True:
        schedule.run_pending()
        time.sleep(1)
