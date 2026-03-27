#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "=================================================="
echo " Installing ShieldKube Agent "
echo "=================================================="

# Check requirements
command -v kubectl >/dev/null 2>&1 || { echo -e "${RED}kubectl is required but it's not installed. Aborting.${NC}"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${RED}docker is required but it's not installed. Aborting.${NC}"; exit 1; }

SHIELDKUBE_URL=${SHIELDKUBE_URL:-"http://host.minikube.internal:8000"}
API_KEY=${SHIELDKUBE_API_KEY:-"shieldkube-default-key-2024"}
CLUSTER_NAME=${CLUSTER_NAME:-"ShieldKube-Managed-Cluster"}
CLUSTER_ID=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)

echo -e "\n${GREEN}Building Docker Image locally...${NC}"
cd agent
docker build -t shieldkube-agent:latest .
cd ..

echo -e "\n${GREEN}Applying Kubernetes Manifests...${NC}"
sed -e "s|{{SHIELDKUBE_URL}}|$SHIELDKUBE_URL|g" \
    -e "s|{{SHIELDKUBE_API_KEY}}|$API_KEY|g" \
    -e "s|{{CLUSTER_NAME}}|$CLUSTER_NAME|g" \
    -e "s|{{CLUSTER_ID}}|$CLUSTER_ID|g" \
    agent-template.yaml > agent-tmp.yaml

kubectl apply -f agent-tmp.yaml
rm agent-tmp.yaml

echo -e "\n${GREEN}Installation Complete!${NC}"
echo "You can check agent logs using: kubectl logs -n shieldkube-agent -l app=shieldkube-agent -f"
