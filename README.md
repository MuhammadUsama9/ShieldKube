# ShieldKube

**ShieldKube** is a professional, high-performance Kubernetes security platform designed for real-time risk auditing and continuous monitoring. It provides deep visibility into your cluster's security posture by analyzing workloads, RBAC permissions, infrastructure vulnerabilities, live metrics, and cluster events.

## Dashboard Overview
> **Note to Contributor**: Please add your screenshots below using `![Dashboard Screenshot](path/to/image.png)`.

![ShieldKube Main Dashboard]() *(Add main dashboard screenshot here)*
![ShieldKube Live Monitoring]() *(Add live monitoring screenshot here)*
![ShieldKube Cluster Events]() *(Add cluster events screenshot here)*

## Key Features

-   **Real-time Risk Radar**: Visualize security threats across different dimensions (Runtime, IAM, Network, etc.).
-   **CVE Workload Audit**: Automated scanning of Pods, Deployments, and Nodes against the latest vulnerability databases.
-   **Live Cluster Monitoring**: Track CPU and Memory utilization for both Pods and Nodes dynamically in real-time.
-   **Cluster Events Stream**: Instant visibility into Kubernetes scheduling actions, warnings, and container lifecycle events.
-   **Secret & ConfigMap Auditor**: Automatically scan for hardcoded credentials, API keys, and weak naming conventions in your cluster configs.
-   **RBAC permission auditing**: Identify wildcard permissions and over-privileged roles.
-   **Interactive remediation**: Apply security patches directly from the dashboard.

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

