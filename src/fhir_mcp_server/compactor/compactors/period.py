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

from ..types.complex_types import Period

logger = logging.getLogger(__name__)


def compact(period: Period) -> str:
    """Compact a Period to "start – end", "from start", or "until end"."""
    # {"start": "2024-01-01", "end": "2024-06-30"} -> "2024-01-01 – 2024-06-30"
    # {"start": "2024-01-01"}                       -> "from 2024-01-01"
    # {"end": "2024-06-30"}                         -> "until 2024-06-30"
    logger.debug(f"Compacting Period: {period}")
    start = str(period.start) if period.start else ""
    end = str(period.end) if period.end else ""
    if start and end:
        compacted = f"{start} – {end}"
    else:
        compacted = f"from {start}" if start else f"until {end}" if end else ""
    logger.debug(f"Compacted Period: '{compacted}'")
    return compacted