# Stage 1: Build the Go Agent
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o shieldkube-go-agent main.go

# Stage 2: Final Image
FROM alpine:3.19

# Install dependencies for running binaries
RUN apk add --no-cache libc6-compat ca-certificates bash

# Copy Trivy from official image
COPY --from=aquasec/trivy:0.49.1 /usr/local/bin/trivy /usr/local/bin/trivy

# Copy kube-bench from official image
COPY --from=aquasec/kube-bench:latest /usr/local/bin/kube-bench /usr/local/bin/kube-bench
# Also copy kube-bench config files which are in /opt/kube-bench/cfg/
COPY --from=aquasec/kube-bench:latest /opt/kube-bench/cfg /opt/kube-bench/cfg

WORKDIR /app
COPY --from=builder /app/shieldkube-go-agent .

ENV SHIELDKUBE_URL="http://localhost:8000"
ENV CLUSTER_ID="go-agent-cluster"
ENV SYNC_INTERVAL_SEC="60"

# Run the agent
CMD ["./shieldkube-go-agent"]
