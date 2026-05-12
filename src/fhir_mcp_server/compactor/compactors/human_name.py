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

from ..types.complex_types import HumanName


from typing import List

logger = logging.getLogger(__name__)


def compact(human_name: HumanName) -> str:
    """Compact a HumanName to "prefix given family suffix"; appends use unless official."""
    # {"use": "official", "family": "Smith", "given": ["John"], "prefix": ["Dr."]} -> "Dr. John Smith"
    # {"use": "nickname", "given": ["Johnny"]}                                      -> "Johnny (nickname)"
    logger.debug(f"Compacting HumanName: {human_name}")
    if human_name.text:
        logger.debug(f"HumanName has 'text' field, returning: '{human_name.text}'")
        return human_name.text
    parts: List[str] = [*(human_name.prefix or []), *(human_name.given or [])]
    if human_name.family:
        parts.append(human_name.family)
    parts.extend(human_name.suffix or [])
    result = " ".join(parts)
    compacted = f"{result} ({human_name.use})" if human_name.use and human_name.use != "official" else result
    logger.debug(f"Compacted HumanName: '{compacted}'")
    return compacted