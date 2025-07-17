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


@pytest_asyncio.fixture
async def mcp_server() -> AsyncGenerator[bool, Any]:
    """Start the MCP server in a subprocess for the test session, streaming stdout in real time."""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "src")
    )
    env["FHIR_SERVER_BASE_URL"] = "https://hapi.fhir.org/baseR4"
    env["FHIR_MCP_HOST"] = "localhost"
    env["FHIR_MCP_PORT"] = "8001"

    logger.info("Starting MCP server with: uv run fhir-mcp-server --disable-auth")
    process = subprocess.Popen(
        ["uv", "run", "fhir-mcp-server", "--disable-auth"],
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

    # Wait for the server to be ready (port 8001 open)
    start = time.time()
    ready = False
    while time.time() - start < 5:  # wait up to 5 seconds
        if process.poll() is not None:
            # Print any remaining output
            if process.stdout is not None:
                for line in process.stdout:
                    logger.debug(f"{line.rstrip()}")
            raise RuntimeError("MCP server process exited before port 8001 was open.")
        try:
            with socket.create_connection(("localhost", 8001), timeout=1):
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
        raise RuntimeError(f"MCP server failed to start or port 8001 not open.")
    logger.info("MCP server is ready on port 8001.")
    yield True
    logger.info("Terminating MCP server.")
    process.terminate()
    process.wait()
