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
from ..types.complex_types import Address
from typing import List

logger = logging.getLogger(__name__)


def compact(address: Address) -> str:
    """Compact an Address to a single line; appends use and type when present."""
    # {"line": ["123 Main St"], "city": "Boston", "district": "Suffolk", "state": "MA", "postalCode": "02101", "country": "US"} -> "123 Main St, Boston Suffolk MA 02101, US"
    # {"text": "123 Main St, Boston MA 02101"}                                                                                  -> "123 Main St, Boston MA 02101"
    # {"use": "home", "type": "postal", "line": ["123 Main St"], "city": "Boston"}                                              -> "123 Main St, Boston (home, postal)"
    logger.debug(f"Compacting address: {address}")
    if address.text:
        logger.debug(f"Address has 'text' field, returning: '{address.text}'")
        return address.text
    parts: List[str] = []
    if address.line:
        parts.append(", ".join(address.line))
    location = " ".join(
        filter(
            None, [address.city or "", address.district or "", address.state or "", address.postalCode or ""]
        )
    )
    if location:
        parts.append(location)
    if address.country:
        parts.append(address.country)
    result = ", ".join(parts)
    qualifiers = ", ".join(filter(None, [address.use or "", address.type or ""]))
    compacted = f"{result} ({qualifiers})" if qualifiers else result
    logger.debug(f"Compacted address: '{compacted}'")
    return compacted
