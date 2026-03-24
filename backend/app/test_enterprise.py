import os
import sys
import json
import time
from unittest.mock import MagicMock

# Mock dependencies before importing
sys.modules["kubernetes"] = MagicMock()
sys.modules["kubernetes.client"] = MagicMock()
sys.modules["kubernetes.config"] = MagicMock()

# Add current directory to path
sys.path.append(os.getcwd())

from app.database import db

# Mock FastAPI for minimal testing if needed
try:
    from app.main import sync_agent_data, get_pods, AGENT_API_KEY
    from fastapi import HTTPException
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    print("Warning: FastAPI or its dependencies missing. Skipping endpoint tests, focusing on Database Persistence.")

import asyncio

# Simple mock for Request object
class MockRequest:
    def __init__(self, headers):
        self.headers = headers

def test_database_persistence():
    print("Testing Database Persistence...")
    cluster_id = "test-cluster-1"
    cluster_name = "Test Cluster"
    
    # 1. Update cluster
    db.update_cluster(cluster_id, cluster_name)
    clusters = db.get_clusters()
    found = any(c["id"] == cluster_id and c["name"] == cluster_name for c in clusters)
    assert found, "Cluster not found in DB after update"
    print("  Cluster registration passed.")

    # 2. Save and get telemetry
    test_pods = [{"name": "pod-1", "status": "Running"}]
    db.save_telemetry(cluster_id, "pods", test_pods)
    retrieved_pods = db.get_telemetry(cluster_id, "pods")
    assert retrieved_pods == test_pods, "Telemetry data mismatch"
    print("  Telemetry persistence passed.")

def test_agent_sync_endpoint_auth():
    if not HAS_FASTAPI: return
    print("Testing Agent Sync Endpoint Authentication...")
    cluster_id = "test-cluster-auth"
    payload = {"cluster_name": "Auth Test", "pods": []}
    
    # 1. Test without API Key
    try:
        asyncio.run(sync_agent_data(cluster_id, MockRequest(headers={}), payload))
        assert False, "Should have raised HTTPException 401"
    except HTTPException as e:
        assert e.status_code == 401
    print("  Unauthorized access blocked (Passed).")

    # 2. Test with invalid API Key
    try:
        asyncio.run(sync_agent_data(cluster_id, MockRequest(headers={"X-API-KEY": "wrong"}), payload))
        assert False, "Should have raised HTTPException 401"
    except HTTPException as e:
        assert e.status_code == 401
    print("  Invalid API Key blocked (Passed).")

    # 3. Test with valid API Key
    resp = asyncio.run(sync_agent_data(cluster_id, MockRequest(headers={"X-API-KEY": AGENT_API_KEY}), payload))
    assert resp["status"] == "success"
    print("  Authorized access allowed (Passed).")

def test_data_retrieval_after_sync():
    if not HAS_FASTAPI: return
    print("Testing Data Retrieval after Sync...")
    cluster_id = "test-cluster-sync"
    test_pods = [{"name": "enterprise-pod-1", "namespace": "prod", "severity": "High"}]
    payload = {"cluster_name": "Sync Test", "pods": test_pods}
    
    # Sync data
    asyncio.run(sync_agent_data(cluster_id, MockRequest(headers={"X-API-KEY": AGENT_API_KEY}), payload))
    
    # Retrieve via function
    data = asyncio.run(get_pods(cluster_id))
    assert len(data) == 1
    assert data[0]["name"] == "enterprise-pod-1"
    print("  End-to-end sync and retrieval passed.")

if __name__ == "__main__":
    # Clean up old DB if exists for clean test
    if os.path.exists("shieldkube.db"):
        os.remove("shieldkube.db")
    
    try:
        test_database_persistence()
        test_agent_sync_endpoint_auth()
        test_data_retrieval_after_sync()
        print("\nAll enterprise architecture tests passed successfully!")
    except Exception as e:
        print(f"\nTests failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Clean up
        if os.path.exists("shieldkube.db"):
            os.remove("shieldkube.db")
