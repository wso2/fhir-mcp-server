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

from .base import FhirTypesBaseModel
from .quantity import Quantity


logger = logging.getLogger(__name__)


class Range(FhirTypesBaseModel):
    low: Optional[Quantity] = None
    high: Optional[Quantity] = None

    def compact(self) -> str:
        """Compact a Range to "low – high", or just low/high if one bound is absent."""
        # {"low": {"value": 3.5, "unit": "mmol/L"}, "high": {"value": 5.5, "unit": "mmol/L"}} -> "3.5 mmol/L – 5.5 mmol/L"
        logger.debug(f"Compacting Range: {self.model_dump_json()}")
        low_s = self.low.compact() if self.low else ""
        high_s = self.high.compact() if self.high else ""
        compacted = f"{low_s} – {high_s}" if low_s and high_s else low_s or high_s
        logger.debug(f"Compacted Range: '{compacted}'")
        return compacted
