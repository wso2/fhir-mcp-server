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
from typing import Literal, Optional

from .period import Period
from .base import FhirTypesBaseModel

logger = logging.getLogger(__name__)


class ContactPoint(FhirTypesBaseModel):
    system: Optional[
        Literal["phone", "fax", "email", "pager", "url", "sms", "other"]
    ] = None
    value: Optional[str] = None
    use: Optional[str] = None
    rank: Optional[int] = None
    period: Optional[Period] = None

    def compact(self) -> str:
        """Compact a ContactPoint to "system: value (use) #rank"."""
        # {"system": "phone", "value": "555-1234", "use": "home"}          -> "phone: 555-1234 (home)"
        # {"system": "email", "value": "john@example.com"}                  -> "email: john@example.com"
        # {"system": "phone", "value": "555-1234", "use": "home", "rank": 1} -> "phone: 555-1234 (home) #1"
        logger.debug(f"Compacting ContactPoint: {self.model_dump_json()}")
        system = self.system or ""
        value = self.value or ""
        result = f"{system}: {value}" if system else value
        if self.use:
            result = f"{result} ({self.use})"
        if self.rank is not None:
            result = f"{result} #{self.rank}"
        logger.debug(f"Compacted ContactPoint: '{result}'")
        return result
