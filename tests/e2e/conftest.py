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

import json
import os
import subprocess
import sys
import time
import logging
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, AsyncGenerator, List, Tuple
import socket
import threading

import pytest_asyncio

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - [MCP SERVER] %(message)s",
)

logger: logging.Logger = logging.getLogger(__name__)

LIVE_FHIR_BASE_URL = "https://hapi.fhir.org/baseR4"


class RecordingFhirServer:
    """A local stand-in FHIR server that records every request it receives.

    The MCP server runs in a separate process, so the pytest process cannot
    patch its HTTP client. Instead the MCP server is pointed at this stub via
    `FHIR_SERVER_BASE_URL`, which makes "did the MCP server call out to the
    FHIR server?" directly observable in `requests`.
    """

    def __init__(self) -> None:
        self.requests: List[Tuple[str, str]] = []
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                recorder.requests.append((self.command, self.path))
                body = json.dumps(
                    {"resourceType": "Patient", "id": "123", "gender": "male"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/fhir+json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

            def log_message(self, format: str, *args: Any) -> None:
                logger.debug("[FHIR STUB] " + format, *args)

        # Port 0 lets the OS pick a free port. 127.0.0.1 rather than
        # "localhost" avoids an IPv6 resolution mismatch on Windows.
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def terminate_process_tree(process: subprocess.Popen) -> None:
    """Kill the server and everything it spawned.

    `uv run fhir-mcp-server` starts the server as a grandchild, so
    `process.terminate()` alone kills only the launcher and leaves the server
    holding port 8001. A later test's readiness probe would then connect to
    that orphan instead of its own server.
    """
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            capture_output=True,
        )
    else:
        process.terminate()
    process.wait()


@asynccontextmanager
async def run_mcp_server(fhir_base_url: str) -> AsyncGenerator[bool, Any]:
    """Start the MCP server in a subprocess, streaming stdout in real time."""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "src")
    )
    env["FHIR_SERVER_BASE_URL"] = fhir_base_url
    env["FHIR_MCP_HOST"] = "localhost"
    env["FHIR_MCP_PORT"] = "8001"
    env["FHIR_SERVER_DISABLE_AUTHORIZATION"] = "True"

    logger.info("Starting MCP server with: uv run fhir-mcp-server")
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
        terminate_process_tree(process)
        raise RuntimeError(f"MCP server failed to start or port 8001 not open.")
    logger.info("MCP server is ready on port 8001.")
    try:
        yield True
    finally:
        logger.info("Terminating MCP server.")
        terminate_process_tree(process)


@pytest_asyncio.fixture
async def mcp_server() -> AsyncGenerator[bool, Any]:
    """MCP server backed by the live public FHIR server."""
    async with run_mcp_server(LIVE_FHIR_BASE_URL) as started:
        yield started


@pytest_asyncio.fixture
async def mcp_server_with_recording_fhir() -> AsyncGenerator[RecordingFhirServer, Any]:
    """MCP server whose FHIR backend is a local recording stub.

    Yields the stub so tests can assert on the requests the MCP server made.
    Never contacts a real FHIR server.
    """
    stub = RecordingFhirServer()
    stub.start()
    try:
        async with run_mcp_server(stub.base_url):
            yield stub
    finally:
        stub.stop()
