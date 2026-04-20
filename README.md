# ShieldKube

**ShieldKube** is a professional, high-performance Kubernetes security platform designed for real-time risk auditing and continuous monitoring. It provides deep visibility into your cluster's security posture by analyzing workloads, RBAC permissions, infrastructure vulnerabilities, live metrics, and cluster events.

## Dashboard Overview
> <img width="1527" height="756" alt="image" src="https://github.com/user-attachments/assets/79d1c921-47cb-414b-8772-e682b49a0e05" />


![ShieldKube Main Dashboard]() *(Add main dashboard screenshot here)*
![ShieldKube Live Monitoring]() *(Add live monitoring screenshot here)*
![ShieldKube Cluster Events]() *(Add cluster events screenshot here)*

## Key Features

-   **MITRE ATT&CK Matrix**: Advanced tactical threat mapping across Initial Access, Execution, Persistence, and more.
-   **AI Security Analyst**: Explainable-AI triaging providing human-readable narratives and remediation advice for detected risks.
-   **NIST 800-53 Compliance**: Comprehensive regulatory auditing against NIST SP 800-53 Rev. 5 controls.
-   **SBOM Dependency Explorer**: Generate and explore CycloneDX-compliant Software Bills of Materials for your container images.
-   **Real-time Risk Radar**: Visualize security threats across different dimensions (Runtime, IAM, Network, etc.).
-   **CVE Workload Audit**: Automated scanning of Pods, Deployments, and Nodes against the latest vulnerability databases.
-   **Live Cluster Monitoring**: Track CPU and Memory utilization for both Pods and Nodes dynamically in real-time.
-   **Secret & ConfigMap Auditor**: Automatically scan for hardcoded credentials, API keys, and weak naming conventions in your cluster configs.
-   **RBAC Permission Vision**: Visualize Subject-to-Role relationships and identify wildcard or over-privileged permissions.
-   **Continuous ML Security Engine**: Adaptive anomaly detection modeling baseline telemetry via an online Stochastic Gradient Descent One-Class SVM.

## Tech Stack

-   **Backend**: Python, FastAPI, Kubernetes Python Client.
-   **Frontend**: React (Vite), Recharts, Premium Glassmorphic Vanilla CSS.
-   **Infrastructure**: Docker, Docker Compose, Kubernetes.

## Getting Started

### Prerequisites

-   Docker & Docker Compose
-   Access to a Kubernetes Cluster (e.g., Minikube with `metrics-server` enabled)

### Local Development

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/MuhammadUsama9/ShieldKube.git
    cd ShieldKube
    ```

2.  **Enable Minikube Metrics** (if using Minikube):
    ```bash
    minikube addons enable metrics-server
    ```

3.  **Run with Docker Compose**:
    ```bash
    docker compose up --build
    ```

4.  **Access the Dashboard**:
    Open [http://localhost:80](http://localhost:80) in your browser.

