# Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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

import asyncio
import json
from collections import deque
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


def build_mcp_test_environment(fhir_base_url: str) -> dict[str, str]:
    """Isolate anonymous test servers from both inherited settings and .env."""
    env = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("FHIR_")
    }
    env["PYTHONPATH"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "src")
    )
    env.update({
        "FHIR_SERVER_BASE_URL": fhir_base_url,
        "FHIR_MCP_HOST": "localhost",
        "FHIR_MCP_PORT": "8001",
        "FHIR_MCP_SERVER_URL": "",
        "FHIR_MCP_REQUEST_TIMEOUT": "30",
        "FHIR_MCP_ENABLE_WRITE_TOOLS": "False",
        "FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES": "1048576",
        "FHIR_MCP_MAX_INTERACTION_RESPONSE_BYTES": "8388608",
        "FHIR_SERVER_DISABLE_AUTHORIZATION": "True",
        # Removing inherited keys is insufficient: ServerConfigs loads .env.
        # Explicit empty values override credentials in that file as well.
        "FHIR_SERVER_ACCESS_TOKEN": "",
        "FHIR_SERVER_CLIENT_ID": "",
        "FHIR_SERVER_CLIENT_SECRET": "",
        "FHIR_SERVER_SCOPES": "",
    })
    return env


class RecordingFhirServer:
    """A local stand-in FHIR server that records every request it receives.

    The MCP server runs in a separate process, so the pytest process cannot
    patch its HTTP client. Instead the MCP server is pointed at this stub via
    `FHIR_SERVER_BASE_URL`, which makes "did the MCP server call out to the
    FHIR server?" directly observable in `requests`.
    """

    def __init__(self) -> None:
        self.requests: List[Tuple[str, str]] = []
        self.authorization_seen: list[bool] = []
        self.records: list[dict] = []
        self.responses = deque()
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                recorder.requests.append((self.command, self.path))
                recorder.authorization_seen.append("Authorization" in self.headers)
                length = int(self.headers.get("Content-Length", "0"))
                request_body = self.rfile.read(length)
                # Tests supply only dummy tokens. The legacy presence-only list remains.
                recorder.records.append({"method": self.command, "path": self.path,
                                         "headers": dict(self.headers), "body": request_body})
                status, headers, payload, delay = recorder.responses.popleft() if recorder.responses else (
                    200, {}, {"resourceType": "Patient", "id": "123", "gender": "male"}, 0)
                if delay:
                    time.sleep(delay)
                if status == 0:
                    self.close_connection = True
                    return
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", headers.pop("Content-Type", "application/fhir+json"))
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle

            def log_message(self, format: str, *args: Any) -> None:
                logger.debug("[FHIR STUB] " + format, *args)

        # Port 0 lets the OS pick a free port. 127.0.0.1 rather than
        # "localhost" avoids an IPv6 resolution mismatch on Windows.
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def queue(self, status=200, body=b"", headers=None, delay=0):
        self.responses.append((status, dict(headers or {}), body, delay))

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def terminate_process_tree(process: subprocess.Popen) -> None:
    """Kill the server and everything it spawned.

    Terminate descendants too: a Windows Python launcher can leave the server
    holding port 8001 if only the parent is terminated. A later readiness probe
    would then connect to that orphan instead of its own server.
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
async def run_mcp_server(fhir_base_url: str, *, settings: dict[str, str] | None = None, port: int = 8001) -> AsyncGenerator[bool, Any]:
    """Start the MCP server in a subprocess, streaming stdout in real time."""
    env = build_mcp_test_environment(fhir_base_url)
    env.update(settings or {})
    env["FHIR_MCP_PORT"] = str(port)

    logger.info("Starting MCP server with the current Python interpreter")
    process = subprocess.Popen(
        [sys.executable, "-m", "fhir_mcp_server"],
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
    while time.time() - start < 15:  # wait up to 5 seconds
        if process.poll() is not None:
            # Print any remaining output
            if process.stdout is not None:
                for line in process.stdout:
                    logger.debug(f"{line.rstrip()}")
            raise RuntimeError("MCP server process exited before port 8001 was open.")
        try:
            with socket.create_connection(("localhost", port), timeout=1):
                ready = True
                break
        except (OSError, ConnectionRefusedError) as ex:
            logger.debug("Waiting until MCP server starts: %s", ex)
            await asyncio.sleep(0.1)
    if not ready:
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
    async with run_mcp_server(LIVE_FHIR_BASE_URL, settings={"FHIR_MCP_ENABLE_WRITE_TOOLS": "True"}) as started:
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
        async with run_mcp_server(stub.base_url, settings={"FHIR_MCP_ENABLE_WRITE_TOOLS": "True"}):
            yield stub
    finally:
        stub.stop()
