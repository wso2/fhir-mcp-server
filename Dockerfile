# ----------------------------------------------------------------------------------------
#
# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
#
# This software is the property of WSO2 LLC. and its suppliers, if any.
# Dissemination of any information or reproduction of any material contained
# herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
# You may not alter or remove any copyright or other notice from copies of this content.
#
# ----------------------------------------------------------------------------------------

# Builder
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app

# Copy source
COPY . .

# Create venv and install in one layer
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
RUN uv venv /opt/venv && \
    uv pip sync requirements.txt && \
    uv pip install .

# Runtime
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    FHIR_MCP_HOST=0.0.0.0 \
    FHIR_MCP_PORT=8000 \
    FHIR_MCP_REQUEST_TIMEOUT=30 

WORKDIR /app

# Use --link for better caching
COPY --from=builder --link /opt/venv /opt/venv
COPY --from=builder --link /app /app

RUN useradd -m -u 10001 appuser
USER 10001

EXPOSE 8000
CMD ["fhir-mcp-server", "--transport", "streamable-http", "--log-level", "INFO"]
