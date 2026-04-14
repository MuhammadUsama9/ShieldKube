import os
import joblib
import numpy as np
from sklearn.linear_model import SGDOneClassSVM, LinearRegression
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any

MODEL_PATH = os.getenv("SHIELDKUBE_ML_MODEL_PATH", "ml_model.pkl")
SCALER_PATH = os.getenv("SHIELDKUBE_ML_SCALER_PATH", "ml_scaler.pkl")

class AnomalyDetector:
    def __init__(self):
        self.model = SGDOneClassSVM(nu=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.history = []
        
        self.load_model()
        
    def load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                self.is_fitted = True
                print(f"ML Model loaded from {MODEL_PATH}")
            except Exception as e:
                print(f"Error loading ML model: {e}")
                self.is_fitted = False

    def save_model(self):
        try:
            joblib.dump(self.model, MODEL_PATH)
            joblib.dump(self.scaler, SCALER_PATH)
        except Exception as e:
            print(f"Error saving ML model: {e}")

    def extract_features(self, payload: Dict[str, Any]) -> np.ndarray:
        # Extract features
        # 1. security_score
        # 2. total_vulnerabilities
        # 3. total_risks
        # 4. avg_cpu_usage
        # 5. avg_mem_usage
        
        summary = payload.get("summary", {})
        security_score = float(summary.get("security_score", 100.0))
        total_vulnerabilities = float(summary.get("total_vulnerabilities", 0.0))
        total_risks = float(summary.get("total_risks", 0.0))
        
        metrics = payload.get("metrics", {})
        nodes = metrics.get("nodes", [])
        
        if nodes:
            avg_cpu = sum(float(n.get("cpu_usage", 0)) for n in nodes) / len(nodes)
            avg_mem = sum(float(n.get("mem_usage", 0)) for n in nodes) / len(nodes)
        else:
            avg_cpu = 0.0
            avg_mem = 0.0
            
        features = [security_score, total_vulnerabilities, total_risks, avg_cpu, avg_mem]
        return np.array(features).reshape(1, -1)

    def process_telemetry(self, cluster_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process the payload to detect anomaly and then update the model continuously.
        Returns the ML insights for this cluster's current state.
        """
        X_raw = self.extract_features(payload)
        
        insight = {
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "status": "Learning" # Initial state if not enough data
        }
        
        if self.is_fitted:
            X_scaled = self.scaler.transform(X_raw)
            # Predict returns 1 for inliers, -1 for outliers
            prediction = self.model.predict(X_scaled)[0]
            # Decision function returns signed distance. 
            # Negative distance -> Anomaly. Positive -> Normal.
            # Convert to anomaly probability using sigmoid over -score.
            score = float(self.model.decision_function(X_scaled)[0])
            anomaly_prob = 1.0 / (1.0 + np.exp(score))
            
            insight["is_anomaly"] = bool(prediction == -1)
            insight["anomaly_score"] = float(anomaly_prob)
            insight["status"] = "Active"
        
        # Continuous learning step
        # Since standard scaler does not support partial_fit properly, we implement an online running mean/var
        self.partial_update_scaler(X_raw)
        X_scaled_new = self.scaler.transform(X_raw)
        self.model.partial_fit(X_scaled_new)
        self.is_fitted = True
        self.save_model()
        
        # Update rolling buffer
        self.history.append(X_raw[0].tolist())
        if len(self.history) > 20:
            self.history.pop(0)

        # Basic Forecasting
        forecast = {"security_score": X_raw[0][0], "avg_cpu": X_raw[0][3]}
        if len(self.history) >= 5:
            seq = np.array(range(len(self.history))).reshape(-1, 1)
            y_score = np.array([h[0] for h in self.history])
            y_cpu = np.array([h[3] for h in self.history])
            
            lr_score = LinearRegression().fit(seq, y_score)
            lr_cpu = LinearRegression().fit(seq, y_cpu)
            
            pred_score = min(100.0, max(0.0, float(lr_score.predict([[len(self.history) + 4]])[0])))
            pred_cpu = max(0.0, float(lr_cpu.predict([[len(self.history) + 4]])[0]))
            forecast["security_score"] = pred_score
            forecast["avg_cpu"] = pred_cpu
            
        insight["forecast"] = forecast
        return insight
        
    def partial_update_scaler(self, X_raw: np.ndarray):
        # StandardScaler partial_fit dynamically updates moving average and variance
        self.scaler.partial_fit(X_raw)

# Singleton instance
anomaly_detector = AnomalyDetector()
