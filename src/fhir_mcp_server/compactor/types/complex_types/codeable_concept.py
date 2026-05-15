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

from .coding import Coding
from .base import FhirTypesBaseModel

logger = logging.getLogger(__name__)


class CodeableConcept(FhirTypesBaseModel):
    text: Optional[str] = None
    coding: Optional[List[Coding]] = None

    def compact(self) -> str:
        """Compact a CodeableConcept: prefers text, then display+code, then system|code."""
        # {"coding": [..., "display": "Body Height"}], "text": "Body Height"} -> "Body Height"
        # {"coding": [{"system": "...", "code": "8302-2", "display": "Body Height"}]}  -> "Body Height (8302-2)"
        # {"coding": [{"system": "http://loinc.org", "code": "8302-2"}]}               -> "http://loinc.org|8302-2"
        logger.debug(f"Compacting CodeableConcept: {self.model_dump_json()}")
        if self.text:
            logger.debug(f"Compacted CodeableConcept using text: '{self.text}'")
            return self.text
        if self.coding:
            # compacted = ", ".join(c.compact() for c in self.coding if c.compact())
            compacted = self.coding[0].compact()
            logger.debug(f"Compacted CodeableConcept using coding: '{compacted}'")
            return compacted
        logger.debug("CodeableConcept has no text or coding — returning empty string")
        return ""
