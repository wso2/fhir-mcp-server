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

from ..types.complex_types import Coding

logger = logging.getLogger(__name__)


def compact(coding: Coding) -> str:
    """Compact a Coding: prefers display+code, then system|code, then code alone."""
    # {"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"} -> "Body Height (8302-2)"
    # {"system": "http://loinc.org", "code": "8302-2"}                            -> "http://loinc.org|8302-2"
    # {"system": "http://loinc.org", "display": "Body Height"}                     -> "Body Height"
    logger.debug(f"Compacting Coding: {coding}")
    if coding.display:
        compacted = f"{coding.display} ({coding.code})" if coding.code else coding.display
        logger.debug(f"Compacted Coding using display: '{compacted}'")
        return compacted
    if coding.system and coding.code:
        compacted = f"{coding.system}|{coding.code}"
        logger.debug(f"No display, falling back to system|code: '{compacted}'")
        return compacted
    compacted = coding.code or (str(coding.system) if coding.system else "")
    logger.debug(f"No display or system+code, falling back to: '{compacted}'")
    return compacted