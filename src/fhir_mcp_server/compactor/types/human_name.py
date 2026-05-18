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
from typing import List, Optional

from .period import Period
from .base import FhirTypesBaseModel

logger = logging.getLogger(__name__)


class HumanName(FhirTypesBaseModel):
    text: Optional[str] = None
    use: Optional[str] = None
    family: Optional[str] = None
    given: Optional[List[str]] = None
    prefix: Optional[List[str]] = None
    suffix: Optional[List[str]] = None
    period: Optional[Period] = None

    def compact(self) -> str:
        """Compact a HumanName to "prefix given family suffix"; appends use unless official."""
        # {"use": "official", "family": "Smith", "given": ["John"], "prefix": ["Dr."]} -> "Dr. John Smith"
        # {"use": "nickname", "given": ["Johnny"]}                                      -> "Johnny (nickname)"
        logger.debug(f"Compacting HumanName: {self.model_dump_json()}")
        if self.text:
            logger.debug(f"HumanName has 'text' field, returning: '{self.text}'")
            return self.text
        parts: List[str] = [*(self.prefix or []), *(self.given or [])]
        if self.family:
            parts.append(self.family)
        parts.extend(self.suffix or [])
        result = " ".join(parts)
        compacted = (
            f"{result} ({self.use})" if self.use and self.use != "official" else result
        )
        logger.debug(f"Compacted HumanName: '{compacted}'")
        return compacted
