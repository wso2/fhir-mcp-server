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

FROM python:3.11-slim

# Install uv (for fast dependency management)
RUN pip install --upgrade pip

# Set workdir
WORKDIR /app

# Copy only requirements first for better caching
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy the rest of the code
COPY . .

# Create a non-root user with UID 10001 and switch to it
RUN useradd -m -u 10001 appuser
USER 10001

# Expose default port
EXPOSE 8000

# Set environment variables (can be overridden at runtime)
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

# Default command to run the server (can be overridden)
CMD ["python", "-m", "fhir_mcp_server"]
