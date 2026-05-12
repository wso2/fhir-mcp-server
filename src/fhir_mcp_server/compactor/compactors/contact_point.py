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

from ..types.complex_types import ContactPoint

logger = logging.getLogger(__name__)


def compact(contact_point: ContactPoint) -> str:
    """Compact a ContactPoint to "system: value (use) #rank"."""
    # {"system": "phone", "value": "555-1234", "use": "home"}          -> "phone: 555-1234 (home)"
    # {"system": "email", "value": "john@example.com"}                  -> "email: john@example.com"
    # {"system": "phone", "value": "555-1234", "use": "home", "rank": 1} -> "phone: 555-1234 (home) #1"
    logger.debug(f"Compacting ContactPoint: {contact_point}")
    system = contact_point.system or ""
    value = contact_point.value or ""
    result = f"{system}: {value}" if system else value
    if contact_point.use:
        result = f"{result} ({contact_point.use})"
    if contact_point.rank is not None:
        result = f"{result} #{contact_point.rank}"
    logger.debug(f"Compacted ContactPoint: '{result}'")
    return result