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

"""
Token-efficient compaction of FHIR General-Purpose Data Types.

Each type is detected and confirmed via Pydantic model_validate.
The resulting typed object is used by the compactor to produce a short,
human-readable string.
"""

from fhir_mcp_server.compactor.registry import COMPLEX_DATA_TYPES
from pydantic import ValidationError
from typing import Any


def compact_resource(data: Any) -> Any:
    """Recursively compact FHIR General-Purpose Data Types in a FHIR response.

    Handled: Coding, CodeableConcept, Quantity (+ subtypes Age/Count/Distance/Duration/
    MoneyQuantity/SimpleQuantity), Range, Ratio, Period, HumanName, Address, ContactPoint,
    Identifier, Attachment, Annotation, Money, Timing, Extension.

    Not handled (returned as-is):
    - SampledData: waveform/time-series data, no meaningful compact text form.
    - Signature: digital signature bytes, not human-readable.
    """

    if isinstance(data, list):  # FHIRPath returns lists — compact each matched value
        return [compact_resource(item) for item in data]
    if not isinstance(data, dict):  # primitive (string, number, bool) — nothing to compact
        return data

    for data_type in COMPLEX_DATA_TYPES:
        try:
            result = data_type.model_validate(data).compact()
            return result if result else data
        except ValidationError:
            continue

    return {k: compact_resource(val) for k, val in data.items()}
