FROM python:3.11-slim

# Install uv (for fast dependency management)
RUN pip install --upgrade pip && pip install uv

# Set workdir
WORKDIR /app

# Copy only requirements first for better caching
COPY requirements.txt ./
RUN uv pip sync --system requirements.txt

# Copy the rest of the code
COPY . .

# Create a non-root user with UID 10001 and switch to it
RUN useradd -m -u 10001 appuser
USER 10001

# Expose default port
EXPOSE 8000

# Set environment variables (can be overridden at runtime)
ENV PYTHONUNBUFFERED=1

# Default command to run the server (can be overridden)
CMD ["uv", "run", "fhir-mcp-server", "--disable-mcp-auth"]
