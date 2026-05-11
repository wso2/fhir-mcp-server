# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""
PromptOpinion FHIR context over HTTP headers (MCP extension ai.promptopinion/fhir-context).

When enabled, X-FHIR-Server-URL, X-FHIR-Access-Token, and optional X-Patient-ID /
refresh headers on each Streamable HTTP POST are correlated with tools/call JSON-RPC
requests so FHIR tools use that server and bearer token instead of static config.
"""

from __future__ import annotations

import json
import logging
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Callable

from mcp.server.fastmcp.server import FastMCP
from mcp.server.models import InitializationOptions
from mcp.server.streamable_http import StreamableHTTPServerTransport
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCRequest, ServerCapabilities, ToolsCapability
from starlette.requests import Request

logger = logging.getLogger(__name__)

PROMPTOPINION_FHIR_CONTEXT_EXTENSION_KEY = "ai.promptopinion/fhir-context"

_PATCH_LOCK = threading.Lock()
_transport_patch_applied = False
_init_patch_by_server: dict[int, Callable[..., InitializationOptions]] = {}


@dataclass(frozen=True)
class PromptOpinionFhirContext:
    """FHIR runtime context supplied by PromptOpinion (or compatible hosts) via HTTP."""

    server_url: str
    access_token: str
    patient_id: str | None = None
    refresh_token: str | None = None
    refresh_url: str | None = None

    def is_complete_for_fhir(self) -> bool:
        return bool(self.server_url and self.access_token)


def _header(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    v = headers.get(name)
    if v is None or not str(v).strip():
        return None
    return str(v).strip()


def parse_promptopinion_headers_from_request(request: Request) -> PromptOpinionFhirContext | None:
    """
    Build context from PromptOpinion headers (case-insensitive via Starlette).
    """
    h = request.headers
    server = _header(h, "x-fhir-server-url")
    token = _header(h, "x-fhir-access-token")
    if not server or not token:
        return None
    patient = _header(h, "x-patient-id")
    refresh_t = _header(h, "x-fhir-refresh-token")
    refresh_u = _header(h, "x-fhir-refresh-url")
    return PromptOpinionFhirContext(
        server_url=server.rstrip("/"),
        access_token=token,
        patient_id=patient,
        refresh_token=refresh_t,
        refresh_url=refresh_u,
    )


_pending: dict[str, PromptOpinionFhirContext] = {}
_active: dict[str, PromptOpinionFhirContext] = {}
_store_lock = threading.Lock()


def _register_pending(request_id: str, ctx: PromptOpinionFhirContext) -> None:
    with _store_lock:
        _pending[request_id] = ctx


def get_promptopinion_fhir_context() -> PromptOpinionFhirContext | None:
    """
    Return FHIR context for the current MCP JSON-RPC request, if any.

    Moves a matching entry from pending (registered when the HTTP transport forwards
    tools/call) into active so multiple lookups within the same tool call succeed.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx

        rid = str(request_ctx.get().request_id)
    except LookupError:
        return None

    with _store_lock:
        if rid in _active:
            return _active[rid]
        ctx = _pending.pop(rid, None)
        if ctx is not None:
            _active[rid] = ctx
        return _active.get(rid)


def clear_promptopinion_context_for_current_request() -> None:
    try:
        from mcp.server.lowlevel.server import request_ctx

        rid = str(request_ctx.get().request_id)
    except LookupError:
        return
    with _store_lock:
        _active.pop(rid, None)
        _pending.pop(rid, None)


class PromptOpinionStreamableHTTPServerTransport(StreamableHTTPServerTransport):
    """
    Captures PromptOpinion FHIR headers for each HTTP POST and ties them to the
    JSON-RPC tools/call id so tool handlers can resolve them from request_ctx.
    """

    _po_capture_headers: PromptOpinionFhirContext | None = None

    @asynccontextmanager
    async def connect(
        self,
    ) -> AsyncGenerator[
        tuple[Any, Any],
        None,
    ]:
        async with super().connect() as streams:
            writer = self._read_stream_writer
            if writer is None:
                yield streams
                return

            original_send = writer.send

            async def wrapped_send(item: SessionMessage | Exception) -> None:
                hdrs = self._po_capture_headers
                if hdrs is not None and isinstance(item, SessionMessage):
                    root = item.message.root
                    if (
                        isinstance(root, JSONRPCRequest)
                        and root.method == "tools/call"
                        and root.id is not None
                    ):
                        _register_pending(str(root.id), hdrs)
                await original_send(item)

            writer.send = wrapped_send  # type: ignore[method-assign]
            try:
                yield streams
            finally:
                writer.send = original_send  # type: ignore[method-assign]

    async def _handle_post_request(self, scope: Any, request: Request, receive: Any, send: Any) -> None:
        self._po_capture_headers = parse_promptopinion_headers_from_request(request)
        try:
            return await super()._handle_post_request(scope, request, receive, send)
        finally:
            self._po_capture_headers = None


class PromptOpinionFastMCP(FastMCP):
    """Clears per-request PromptOpinion FHIR context after each tools/call completes."""

    async def call_tool(self, name: str, arguments: dict[str, Any]):  # type: ignore[override]
        try:
            return await super().call_tool(name, arguments)
        finally:
            clear_promptopinion_context_for_current_request()


def _merge_capabilities_extensions(
    caps: ServerCapabilities,
    extension_payload: dict[str, Any],
) -> ServerCapabilities:
    dumped = caps.model_dump(mode="python", exclude_none=True)
    existing = dumped.get("extensions")
    if isinstance(existing, dict):
        merged_ext = {**existing, **extension_payload}
    else:
        merged_ext = dict(extension_payload)
    dumped["extensions"] = merged_ext
    return ServerCapabilities.model_validate(dumped)


def _patch_initialization_options(mcp_server: Any, scopes: list[dict[str, Any]]) -> None:
    sid = id(mcp_server)
    if sid in _init_patch_by_server:
        return

    original = mcp_server.create_initialization_options

    def wrapped(
        notification_options: Any | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        opts = original(
            notification_options=notification_options,
            experimental_capabilities=experimental_capabilities,
        )
        extension_block = {
            PROMPTOPINION_FHIR_CONTEXT_EXTENSION_KEY: {"scopes": scopes},
        }
        new_caps = _merge_capabilities_extensions(opts.capabilities, extension_block)
        return InitializationOptions(
            server_name=opts.server_name,
            server_version=opts.server_version,
            capabilities=new_caps,
            instructions=opts.instructions,
        )

    mcp_server.create_initialization_options = wrapped  # type: ignore[method-assign]
    _init_patch_by_server[sid] = original


def apply_promptopinion_patches(mcp: FastMCP, scopes: list[dict[str, Any]]) -> None:
    """
    Install Streamable HTTP transport subclass and initialize-result extension.

    Idempotent for process lifetime. Must run before the Streamable HTTP app is built.
    """
    global _transport_patch_applied

    _patch_initialization_options(mcp._mcp_server, scopes)

    with _PATCH_LOCK:
        if _transport_patch_applied:
            return
        import mcp.server.streamable_http as sh
        import mcp.server.streamable_http_manager as shm

        sh.StreamableHTTPServerTransport = PromptOpinionStreamableHTTPServerTransport
        shm.StreamableHTTPServerTransport = PromptOpinionStreamableHTTPServerTransport
        _transport_patch_applied = True
        logger.info(
            "PromptOpinion FHIR context extension enabled (transport + initialize capabilities)."
        )


def default_promptopinion_scopes_from_config(server_scopes: str) -> list[dict[str, Any]]:
    """
    Derive extension scope objects from FHIR_SERVER_SCOPES when JSON scopes are not set.

    Each scope name is advertised as optional unless the string 'offline_access' is
    present, in which case that scope is included once for refresh-token support.
    """
    parts = [p.strip() for p in server_scopes.split() if p.strip()]
    out: list[dict[str, Any]] = []
    for name in parts:
        out.append({"name": name})
    return out


def parse_promptopinion_scopes_json(raw: str) -> list[dict[str, Any]]:
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("Invalid FHIR_PROMPTOPINION_CONTEXT_SCOPES_JSON: %s", e)
        return []
    if not isinstance(data, list):
        return []
    scopes: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict) and "name" in item and item["name"]:
            entry: dict[str, Any] = {"name": str(item["name"])}
            if item.get("required") is True:
                entry["required"] = True
            scopes.append(entry)
    return scopes


def resolve_promptopinion_scopes_for_initialize(config: Any) -> list[dict[str, Any]]:
    parsed = parse_promptopinion_scopes_json(
        getattr(config, "promptopinion_fhir_context_scopes_json", "") or ""
    )
    if parsed:
        return parsed
    derived = default_promptopinion_scopes_from_config(config.server_scopes or "")
    if derived:
        return derived
    return [{"name": "patient/Patient.rs", "required": True}]
