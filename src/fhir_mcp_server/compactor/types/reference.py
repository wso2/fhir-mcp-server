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

from typing import Optional

from .identifier import Identifier
from .base import FhirTypesBaseModel


class Reference(FhirTypesBaseModel):
    reference: Optional[str] = None
    type: Optional[str] = None
    identifier: Optional[Identifier] = None
    display: Optional[str] = None

    def compact(self) -> str:
        # {"display": "Dr. Jane Doe"}                                                              -> "Dr. Jane Doe"
        # {"reference": "Patient/123"}                                                             -> "Patient/123"
        # {"type": "Patient", "identifier": {"system": "http://hospital.org/mrn", "value": "X"}} -> "Patient: http://hospital.org/mrn|X"
        if self.display:
            return self.display
        if self.reference:
            return self.reference
        if self.identifier:
            id_str = self.identifier.compact()
            return f"{self.type}: {id_str}" if self.type else id_str
        return self.type or ""


# resolve circular ref with Identifier
Identifier.model_rebuild()
