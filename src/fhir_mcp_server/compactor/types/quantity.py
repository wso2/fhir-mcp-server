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
from typing import Optional, Union

# from fhir_mcp_server.compactor.compactors import quantity

from .base import FhirTypesBaseModel

logger = logging.getLogger(__name__)


class Quantity(FhirTypesBaseModel):
    value: Optional[Union[int, float]] = None
    comparator: Optional[str] = None
    unit: Optional[str] = None
    system: Optional[str] = None
    code: Optional[str] = None

    def compact(self) -> str:
        """Compact a Quantity value. Also handles constrained subtypes Age, Count, Distance, Duration, MoneyQuantity, SimpleQuantity."""
        # {"value": 7.2, "unit": "mmol/L"}                      -> "7.2 mmol/L"
        # {"value": 5.0, "comparator": ">=", "unit": "mg/dL"}   -> ">=5 mg/dL"
        logger.debug(f"Compacting Quantity: {self.model_dump_json()}")
        value_s = f"{float(self.value):g}" if self.value is not None else ""
        if self.comparator and value_s:
            logger.debug(
                f"Quantity has comparator '{self.comparator}', prepending to value"
            )
            value_s = f"{self.comparator}{value_s}"
        unit = self.unit or self.code
        if unit and value_s:
            compacted = f"{value_s} {unit}"
        else:
            compacted = value_s or unit or ""
        logger.debug(f"Compacted Quantity: '{compacted}'")
        return compacted
