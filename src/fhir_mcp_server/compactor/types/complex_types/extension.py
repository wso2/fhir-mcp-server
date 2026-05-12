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

from pydantic import BaseModel, ConfigDict, model_validator
from typing import List, Optional


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
