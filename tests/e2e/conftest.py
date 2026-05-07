# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

import os
import subprocess
import time
import logging
from typing import Any, AsyncGenerator
import socket
import threading

import pytest_asyncio

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - [MCP SERVER] %(message)s",
)

logger: logging.Logger = logging.getLogger(__name__)


def _start_mcp_server(port: int, extra_env: dict) -> subprocess.Popen:
    """Start the MCP server in a subprocess, streaming stdout in real time."""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "src")
    )
    env["FHIR_SERVER_BASE_URL"] = "https://hapi.fhir.org/baseR4"
    env["FHIR_MCP_HOST"] = "localhost"
    env["FHIR_MCP_PORT"] = str(port)
    env["FHIR_SERVER_DISABLE_AUTHORIZATION"] = "True"
    env.update(extra_env)

    logger.info(f"Starting MCP server on port {port} with: uv run fhir-mcp-server")
    process = subprocess.Popen(
        ["uv", "run", "fhir-mcp-server"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,
    )

    # Start a background thread to stream server output
    def stream_output():
        if process.stdout is not None:
            for line in iter(process.stdout.readline, ""):
                logger.debug(f"{line.rstrip()}")

    t = threading.Thread(target=stream_output, daemon=True)
    t.start()

    # Wait for the server to be ready
    start = time.time()
    ready = False
    while time.time() - start < 5:  # wait up to 5 seconds
        if process.poll() is not None:
            # Print any remaining output
            if process.stdout is not None:
                for line in process.stdout:
                    logger.debug(f"{line.rstrip()}")
            raise RuntimeError(f"MCP server process exited before port {port} was open.")
        try:
            with socket.create_connection(("localhost", port), timeout=1):
                ready = True
                break
        except (OSError, ConnectionRefusedError) as ex:
            logger.debug("Waiting until MCP server starts: %s", ex)
            time.sleep(0.5)
    if not ready:
        if process.stdout is not None:
            for line in process.stdout:
                logger.debug(f"{line.rstrip()}")
        process.terminate()
        process.wait()
        raise RuntimeError(f"MCP server failed to start or port {port} not open.")
    logger.info(f"MCP server is ready on port {port}.")
    return process


@pytest_asyncio.fixture
async def mcp_server() -> AsyncGenerator[bool, Any]:
    """MCP server with JSON output on port 8001."""
    process = _start_mcp_server(8001, {"FHIR_JSON_OUTPUT": "true"})
    yield True
    logger.info("Terminating MCP server (json output).")
    process.terminate()
    process.wait()


@pytest_asyncio.fixture
async def mcp_server_token_efficient() -> AsyncGenerator[bool, Any]:
    """MCP server with token efficient output on port 8002."""
    process = _start_mcp_server(8002, {"FHIR_JSON_OUTPUT": "false"})
    yield True
    logger.info("Terminating MCP server (token efficient output).")
    process.terminate()
    process.wait()
