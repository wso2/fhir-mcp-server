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

"""Exceptions shared by the MCP tools."""


class FhirAuthenticationError(Exception):
    """The request has no usable FHIR identity."""


class FhirInputError(Exception):
    """Tool input was rejected before any request was sent."""

    def __init__(self, message: str, code: str = "invalid"):
        """Attach the FHIR issue code to report for this validation failure."""
        super().__init__(message)
        self.code = code


class FhirTransportError(Exception):
    """A request to the FHIR server failed without a usable response."""

    def __init__(
        self,
        kind: str,
        message: str,
        *,
        status: int | None = None,
        headers: dict[str, str] | None = None,
        uncertain: bool = True,
    ):
        """Record the failure kind, any observed response and whether the server may have
        applied the request.
        """
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.headers = headers or {}
        self.uncertain = uncertain
