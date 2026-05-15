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
from datetime import date, datetime
from typing import Optional, Union, List

# from fhir_mcp_server.compactor.compactors import annotation

from .reference import Reference
from .base import FhirTypesBaseModel


logger = logging.getLogger(__name__)


class Annotation(FhirTypesBaseModel):
    text: Optional[str] = None
    authorString: Optional[str] = None
    authorReference: Optional[Reference] = None
    time: Optional[Union[str, date, datetime]] = None


    def compact(self) -> str:
        """Compact an Annotation to "text (author, time)"; author/time included per spec warning on modifying information."""
        # {"text": "Patient was fasting", "time": "2024-01-01T09:00:00Z"}                          -> "Patient was fasting (2024-01-01T09:00:00Z)"
        # {"text": "Patient was fasting", "authorString": "Dr. Smith", "time": "2024-01-01"}       -> "Patient was fasting (Dr. Smith, 2024-01-01)"
        logger.debug(f"Compacting annotation: {self.model_dump_json()}")
        meta: List[str] = []
        if self.authorString:
            meta.append(self.authorString)
        elif self.authorReference and self.authorReference.reference:
            logger.debug(
                f"No authorString, falling back to authorReference: '{self.authorReference.reference}'"
            )
            meta.append(self.authorReference.reference)
        if self.time:
            t = (
                self.time.isoformat()
                if hasattr(self.time, "isoformat")
                else str(self.time)
            )
            meta.append(t.replace("+00:00", "Z"))
        text = self.text or ""
        compacted = f"{text} ({', '.join(meta)})" if meta else text
        logger.debug(f"Compacted annotation: '{compacted}'")
        return compacted
    