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

from ..types.complex_types import CodeableConcept

logger = logging.getLogger(__name__)


def compact(codeable_concept: CodeableConcept) -> str:
    """Compact a CodeableConcept: prefers text, then display+code, then system|code."""
    # {"coding": [..., "display": "Body Height"}], "text": "Body Height"} -> "Body Height"
    # {"coding": [{"system": "...", "code": "8302-2", "display": "Body Height"}]}  -> "Body Height (8302-2)"
    # {"coding": [{"system": "http://loinc.org", "code": "8302-2"}]}               -> "http://loinc.org|8302-2"
    logger.debug(f"Compacting CodeableConcept: {codeable_concept}")
    if codeable_concept.text:
        logger.debug(f"Compacted CodeableConcept using text: '{codeable_concept.text}'")
        return codeable_concept.text
    if codeable_concept.coding:
        first = codeable_concept.coding[0]
        if first.display:
            compacted = f"{first.display} ({first.code})" if first.code else first.display
            logger.debug(f"Compacted CodeableConcept using coding display: '{compacted}'")
            return compacted
        if first.system and first.code:
            compacted = f"{first.system}|{first.code}"
            logger.debug(f"No display, falling back to system|code: '{compacted}'")
            return compacted
        if first.code:
            logger.debug(f"No display or system, falling back to code only: '{first.code}'")
            return first.code
    logger.debug("CodeableConcept has no text, coding display, system, or code — returning empty string")
    return ""