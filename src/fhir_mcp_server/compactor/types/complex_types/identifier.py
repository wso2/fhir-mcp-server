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
from typing import TYPE_CHECKING, Optional

from .codeable_concept import CodeableConcept
from .period import Period
from .base import FhirTypesBaseModel

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from . import Reference


class Identifier(FhirTypesBaseModel):
    system: Optional[str] = None
    value: Optional[str] = None
    use: Optional[str] = None
    type: Optional[CodeableConcept] = None
    period: Optional[Period] = None
    assigner: Optional["Reference"] = None

    def compact(self) -> str:
        """Compact an Identifier to "type: system|value [use]"."""
        # {"system": "http://hospital.org/mrn", "value": "MRN123", "use": "official"}                    -> "http://hospital.org/mrn|MRN123 [official]"
        # {"type": {"text": "MRN"}, "system": "http://hospital.org/mrn", "value": "MRN123"}              -> "MRN: http://hospital.org/mrn|MRN123"
        logger.debug(f"Compacting Identifier: {self}")
        system = str(self.system) if self.system else ""
        value = self.value or ""
        result = f"{system}|{value}" if system and value else value or system
        if self.use:
            result = f"{result} [{self.use}]"
        if self.type:
            type_label = self.type.compact()
            if type_label:
                result = f"{type_label}: {result}"
        logger.debug(f"Compacted Identifier: '{result}'")
        return result
