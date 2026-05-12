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

from ..types.complex_types import Ratio
from . import quantity

logger = logging.getLogger(__name__)


def compact(ratio: Ratio) -> str:
    """Compact a Ratio to "numerator/denominator"; returns empty string if either side is absent."""
    # {"numerator": {"value": 1, "unit": "mg"}, "denominator": {"value": 10, "unit": "mL"}} -> "1 mg/10 mL"
    logger.debug(f"Compacting Ratio: {ratio}")
    if not ratio.numerator or not ratio.denominator:
        logger.debug("Ratio missing numerator or denominator")
        return ""
    compacted = f"{quantity.compact(ratio.numerator)}/{quantity.compact(ratio.denominator)}"
    logger.debug(f"Compacted Ratio: '{compacted}'")
    return compacted
