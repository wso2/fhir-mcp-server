# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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

import logging
from typing import Optional

# from fhir_mcp_server.compactor.compactors import coding

from .base import FhirTypesBaseModel

logger = logging.getLogger(__name__)


class Coding(FhirTypesBaseModel):
    system: Optional[str] = None
    version: Optional[str] = None
    code: Optional[str] = None
    display: Optional[str] = None
    userSelected: Optional[bool] = None

    def compact(self) -> str:
        """Compact a Coding: prefers display+code, then system|code, then code alone."""
        # {"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"} -> "Body Height (8302-2)"
        # {"system": "http://loinc.org", "code": "8302-2"}                            -> "http://loinc.org|8302-2"
        # {"system": "http://loinc.org", "display": "Body Height"}                     -> "Body Height"
        logger.debug(f"Compacting Coding: {self.model_dump_json()}")
        if self.display:
            compacted = f"{self.display} ({self.code})" if self.code else self.display
            logger.debug(f"Compacted Coding using display: '{compacted}'")
            return compacted
        if self.system and self.code:
            compacted = f"{self.system}|{self.code}"
            logger.debug(f"No display, falling back to system|code: '{compacted}'")
            return compacted
        compacted = self.code or ""
        logger.debug(f"No display or system+code, falling back to: '{compacted}'")
        return compacted
