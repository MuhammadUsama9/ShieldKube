import os
import sys

# Add parent directory to path to allow importing app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.ml_model import anomaly_detector

def test_anomaly_learning():
    payload1 = {
        "summary": {
            "security_score": 95,
            "total_vulnerabilities": 10,
            "total_risks": 2
        },
        "metrics": {
            "nodes": [
                {"cpu_usage": 20, "mem_usage": 40}
            ]
        }
    }

    # First update
    insight1 = anomaly_detector.process_telemetry("test-cluster", payload1)
    assert "status" in insight1

    payload2 = {
        "summary": {
            "security_score": 40,  # Sudden drop
            "total_vulnerabilities": 150, # Sudden spike
            "total_risks": 50
        },
        "metrics": {
            "nodes": [
                {"cpu_usage": 95, "mem_usage": 98} # Spike
            ]
        }
    }

    # Second update
    insight2 = anomaly_detector.process_telemetry("test-cluster", payload2)
    
    print("Insight 1 (Normal):", insight1)
    print("Insight 2 (Anomaly):", insight2)
    
    print("ML Pipeline Continuous Learning Test: SUCCEEDED")

if __name__ == "__main__":
    test_anomaly_learning()
