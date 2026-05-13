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
from typing import List
from ..types.complex_types import Annotation

logger = logging.getLogger(__name__)


def compact(annotation: Annotation) -> str:
    """Compact an Annotation to "text (author, time)"; author/time included per spec warning on modifying information."""
    # {"text": "Patient was fasting", "time": "2024-01-01T09:00:00Z"}                          -> "Patient was fasting (2024-01-01T09:00:00Z)"
    # {"text": "Patient was fasting", "authorString": "Dr. Smith", "time": "2024-01-01"}       -> "Patient was fasting (Dr. Smith, 2024-01-01)"
    logger.debug(f"Compacting annotation: {annotation}")
    meta: List[str] = []
    if annotation.authorString:
        meta.append(annotation.authorString)
    elif annotation.authorReference and annotation.authorReference.reference:
        logger.debug(
            f"No authorString, falling back to authorReference: '{annotation.authorReference.reference}'"
        )
        meta.append(annotation.authorReference.reference)
    if annotation.time:
        t = (
            annotation.time.isoformat()
            if hasattr(annotation.time, "isoformat")
            else str(annotation.time)
        )
        meta.append(t.replace("+00:00", "Z"))
    text = annotation.text or ""
    compacted = f"{text} ({', '.join(meta)})" if meta else text
    logger.debug(f"Compacted annotation: '{compacted}'")
    return compacted
