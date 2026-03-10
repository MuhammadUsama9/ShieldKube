# 🛡️ ShieldKube

**ShieldKube** is a professional, high-performance Kubernetes security platform designed for real-time risk auditing and continuous monitoring. It provides deep visibility into your cluster's security posture by analyzing workloads, RBAC permissions, and infrastructure vulnerabilities.

## Key Features

-   **Real-time Risk Radar**: Visualize security threats across different dimensions (Runtime, IAM, Network, etc.).
-   **CVE Workload Audit**: Automated scanning of Pods, Deployments, and Nodes against the latest vulnerability databases.
-   **RBAC permission auditing**: Identify wildcard permissions and over-privileged roles.
-   **Security compliance mapping**: Automated checks for SOC2 and HIPAA standards.
-   **Interactive remediation**: Apply security patches directly from the dashboard.

## Tech Stack

-   **Backend**: Python, FastAPI, Kubernetes Python Client.
-   **Frontend**: React (Vite), Recharts, Vanilla CSS (Premium Aesthetics).
-   **Infrastructure**: Docker, Docker Compose, Kubernetes.

## Getting Started

### Prerequisites

-   Docker & Docker Compose
-   Access to a Kubernetes Cluster (or Minikube/Kind)

### Local Development

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/MuhammadUsama9/ShieldKube.git
    cd ShieldKube
    ```

2.  **Run with Docker Compose**:
    ```bash
    docker-compose up --build
    ```

3.  **Access the Dashboard**:
    Open [http://localhost:5173](http://localhost:5173) in your browser.

