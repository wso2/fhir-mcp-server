# Fix: Architecture compatibility issue causing exec format error on amd64

## Problem

The current Docker images fail to run on amd64 architecture with the following error:

```
exec /opt/venv/bin/fhir-mcp-server: exec format error
```

This prevents deployment on standard AWS EKS clusters and other amd64 infrastructure.

## Root Cause

The Dockerfile uses multi-stage builds without explicit platform specifications. Without `--platform` flags, Docker may pull different architectures for the builder and runtime stages, resulting in binaries compiled for the wrong architecture.

## Solution

This PR adds explicit platform specifications using Docker build arguments:

```dockerfile
ARG BUILDPLATFORM
ARG TARGETPLATFORM

FROM --platform=$TARGETPLATFORM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
FROM --platform=$TARGETPLATFORM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS runtime
```

## Testing

### Test Environment
- **Cluster:** AWS EKS (ap-southeast-2)
- **Node Architecture:** amd64
- **Container Runtime:** containerd 1.7.28+bottlerocket
- **Validation:** 20+ minutes in production

### Test Results

| Image | Status | Details |
|-------|--------|---------|
| `latest` (before) | ❌ Failed | exec format error |
| Built with fix | ✅ Success | Running in production |

## Multi-Architecture Build

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t wso2/fhir-mcp-server:latest \
  --push .
```

## Benefits

1. ✅ Enables amd64 deployment
2. ✅ Maintains compatibility
3. ✅ Enables multi-arch support
4. ✅ Production validated
