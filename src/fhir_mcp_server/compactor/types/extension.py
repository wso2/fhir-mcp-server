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
from pydantic import BaseModel, ConfigDict, model_validator
from typing import List, Optional

logger = logging.getLogger(__name__)


class Extension(BaseModel):
    model_config = ConfigDict(extra="allow")  # captures value[x] polymorphic fields
    url: str
    extension: Optional[List["Extension"]] = None

    @model_validator(mode="before")
    @classmethod
    def _only_extension_keys(cls, data: dict) -> dict:
        _allowed = {"url", "id", "extension"}
        for key in data:
            if key not in _allowed and not key.startswith("value"):
                raise ValueError(f"Unexpected key '{key}' in Extension")
        return data

    def compact(self) -> str | dict:
        """Compact a FHIR extension to 'url|value' format.

        For nested extensions returns a dict keyed by sub-URL so TOON renders each on its own line.
        Returns "" when the value can't be reduced — caller returns raw dict.
        """
        logger.debug(f"Compacting extension: {self.model_dump_json()}")
        url = self.url

        if self.extension:
            logger.debug(f"Extension has nested extensions under url: '{url}'")
            result: dict = {}
            for e in self.extension:
                sub_url = e.url
                value_str = e._extract_extension_value()
                if not value_str:
                    continue
                if sub_url in result:
                    existing = result[sub_url]
                    result[sub_url] = (
                        existing if isinstance(existing, list) else [existing]
                    )
                    result[sub_url].append(value_str)
                else:
                    result[sub_url] = value_str
            if result:
                compacted = {"url": url, **result} if url else result
                logger.debug(f"Compacted nested extension: {compacted}")
                return compacted
            logger.debug(
                "Nested extension yielded no compactable values, returning empty string"
            )
            return ""

        value_str = self._extract_extension_value()
        if not value_str:
            logger.debug(
                f"Extension url '{url}' has no extractable value, returning empty string"
            )
            return ""
        compacted = f"{url}|{value_str}" if url else value_str
        logger.debug(f"Compacted extension: '{compacted}'")
        return compacted

    def _extract_extension_value(self) -> str:
        """Extract just the value from an extension, without the URL label."""
        # e.g. for {"url": "http://example.com/ext", "valueString": "hello"} returns "hello"
        value_fields = {
            k: v for k, v in self.model_extra.items() if k.startswith("value")
        }
        if len(value_fields) != 1:
            return ""
        val = next(iter(value_fields.values()))
        if isinstance(val, (str, bool)):
            return str(val)
        if isinstance(val, float):
            return f"{val:g}"
        if isinstance(val, int):
            return str(val)
        if isinstance(val, dict):
            from fhir_mcp_server.compactor.dispatch import compact_resource

            compacted = compact_resource(val)
            return compacted if isinstance(compacted, str) else ""
        return ""
