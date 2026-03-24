FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir requests kubernetes schedule

# Copy agent code and scanner module
COPY agent.py .
COPY app/ ./app/

# Environment defaults (overridden by K8s Deployment)
ENV SHIELDKUBE_URL=http://localhost:8000
ENV CLUSTER_ID=remote-cluster
ENV CLUSTER_NAME="Remote Cluster"
ENV SHIELDKUBE_API_KEY=shieldkube-default-key-2024
ENV SYNC_INTERVAL_SEC=60
ENV MOCK_MODE=false

# Run with unbuffered output for cleaner logs
CMD ["python", "-u", "agent.py"]
