#!/usr/bin/env python3
import os
import sys
import requests
from kubernetes import client, config
from app.scanner import K8sScanner

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def run_diagnostics():
    print("="*50)
    print(" ShieldKube Agent Troubleshooting Utility")
    print("="*50)
    print("")

    # 1. API Key Check
    api_key = os.getenv("SHIELDKUBE_API_KEY")
    if api_key:
        print(f"[{GREEN}PASS{RESET}] API_KEY is set in environment.")
    else:
        print(f"[{RED}FAIL{RESET}] API_KEY is MISSING in environment.")

    # 2. ShieldKube URL Check
    url = os.getenv("SHIELDKUBE_URL", "http://host.minikube.internal:8000")
    print(f"Testing connectivity to ShieldKube Backend: {url}")
    try:
        res = requests.get(f"{url}/docs", timeout=5)
        if res.status_code == 200:
            print(f"[{GREEN}PASS{RESET}] Backend reachable (HTTP 200).")
        else:
            print(f"[{RED}WARN{RESET}] Backend reachable but returned HTTP {res.status_code}.")
    except Exception as e:
         print(f"[{RED}FAIL{RESET}] Backend unreachable: {str(e)}")

    # 3. K8s Connectivity Check
    print("\nTesting Kubernetes API Connectivity...")
    scanner = K8sScanner(mock_mode=False)
    if scanner.is_connected:
        print(f"[{GREEN}PASS{RESET}] K8s API Connection established successfully.")
    else:
        print(f"[{RED}FAIL{RESET}] K8s API Connection failed. Running outside cluster or missing kubeconfig?")

    # 4. RBAC / Privilege Check
    print("\nTesting RBAC Privileges (List Pods across all namespaces)...")
    if scanner.is_connected:
        try:
            pods = scanner.v1.list_pod_for_all_namespaces(limit=1).items
            print(f"[{GREEN}PASS{RESET}] RBAC allows listing pods.")
        except Exception as e:
            print(f"[{RED}FAIL{RESET}] RBAC permission denied: {e}")
    else:
        print(f"[{RED}SKIP{RESET}] Cannot test RBAC without valid K8s connection.")

    print("\nDiagnostics complete.")

if __name__ == "__main__":
    run_diagnostics()
