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

from . import codeable_concept
from ..types.complex_types import Identifier

logger = logging.getLogger(__name__)


def compact(identifier: Identifier) -> str:
    """Compact an Identifier to "type: system|value [use]"."""
    # {"system": "http://hospital.org/mrn", "value": "MRN123", "use": "official"}                    -> "http://hospital.org/mrn|MRN123 [official]"
    # {"type": {"text": "MRN"}, "system": "http://hospital.org/mrn", "value": "MRN123"}              -> "MRN: http://hospital.org/mrn|MRN123"
    logger.debug(f"Compacting Identifier: {identifier}")
    system = str(identifier.system) if identifier.system else ""
    value = identifier.value or ""
    result = f"{system}|{value}" if system and value else value or system
    if identifier.use:
        result = f"{result} [{identifier.use}]"
    if identifier.type:
        type_label = codeable_concept.compact(identifier.type)
        if type_label:
            result = f"{type_label}: {result}"
    logger.debug(f"Compacted Identifier: '{result}'")
    return result