# Stage 1: Build the Go Agent
FROM golang:1.21-alpine AS builder

WORKDIR /app
# We will initialize the go module dynamically to avoid needing a manual go.mod with complex transitive dependencies
COPY . .
RUN go mod init shieldkube-go && \
    go get k8s.io/client-go@v0.29.2 && \
    go get k8s.io/api@v0.29.2 && \
    go get k8s.io/apimachinery@v0.29.2 && \
    go mod tidy

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o shieldkube-go-agent main.go

# Stage 2: Final Image with Trivy
FROM alpine:3.19

# Install curl, jq, and other utilities
RUN apk add --no-cache curl jq bash

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.49.1

# Install kube-bench
RUN curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.17/kube-bench_0.6.17_linux_amd64.tar.gz -o kube-bench.tar.gz && \
    tar -xvf kube-bench.tar.gz && \
    mv kube-bench /usr/local/bin/ && \
    rm kube-bench.tar.gz

WORKDIR /app
COPY --from=builder /app/shieldkube-go-agent .

ENV SHIELDKUBE_URL="http://localhost:8000"
ENV CLUSTER_ID="go-agent-cluster"
ENV SYNC_INTERVAL_SEC="60"

# Run the agent
CMD ["./shieldkube-go-agent"]
