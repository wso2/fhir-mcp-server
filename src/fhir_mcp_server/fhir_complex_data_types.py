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
Minimal Pydantic models for the FHIR data types used by the compactor.

extra="forbid" prevents false-positive type matches (e.g. Attachment matching
an Extension dict via the shared "url" field). id and extension are added to
FhirBaseModel because any FHIR element may carry them.
"""

from datetime import date, datetime
from typing import List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict


class FhirBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Optional[str] = None
    extension: Optional[List[dict]] = None


class Coding(FhirBaseModel):
    system: Optional[str] = None
    version: Optional[str] = None
    code: Optional[str] = None
    display: Optional[str] = None
    userSelected: Optional[bool] = None


class CodeableConcept(FhirBaseModel):
    text: Optional[str] = None
    coding: Optional[List[Coding]] = None


class Quantity(FhirBaseModel):
    value: Optional[Union[int, float]] = None
    comparator: Optional[str] = None
    unit: Optional[str] = None
    system: Optional[str] = None
    code: Optional[str] = None


class Range(FhirBaseModel):
    low: Optional[Quantity] = None
    high: Optional[Quantity] = None


class Ratio(FhirBaseModel):
    numerator: Optional[Quantity] = None
    denominator: Optional[Quantity] = None


class Period(FhirBaseModel):
    start: Optional[Union[str, date, datetime]] = None
    end: Optional[Union[str, date, datetime]] = None


class HumanName(FhirBaseModel):
    text: Optional[str] = None
    use: Optional[str] = None
    family: Optional[str] = None
    given: Optional[List[str]] = None
    prefix: Optional[List[str]] = None
    suffix: Optional[List[str]] = None
    period: Optional[Period] = None


class Address(FhirBaseModel):
    text: Optional[str] = None
    use: Optional[str] = None
    type: Optional[str] = None
    line: Optional[List[str]] = None
    city: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    postalCode: Optional[str] = None
    country: Optional[str] = None
    period: Optional[Period] = None


class ContactPoint(FhirBaseModel):
    system: Optional[
        Literal["phone", "fax", "email", "pager", "url", "sms", "other"]
    ] = None
    value: Optional[str] = None
    use: Optional[str] = None
    rank: Optional[int] = None
    period: Optional[Period] = None


class Identifier(FhirBaseModel):
    system: Optional[str] = None
    value: Optional[str] = None
    use: Optional[str] = None
    type: Optional[CodeableConcept] = None
    period: Optional[Period] = None
    assigner: Optional["Reference"] = None


class Attachment(FhirBaseModel):
    contentType: Optional[str] = None
    language: Optional[str] = None
    url: Optional[str] = None
    size: Optional[int] = None
    hash: Optional[Union[bytes, str]] = None
    title: Optional[str] = None
    creation: Optional[Union[str, date, datetime]] = None
    data: Optional[Union[bytes, str]] = None


class Reference(FhirBaseModel):
    reference: Optional[str] = None
    type: Optional[str] = None
    identifier: Optional[Identifier] = None
    display: Optional[str] = None


class Annotation(FhirBaseModel):
    text: Optional[str] = None
    authorString: Optional[str] = None
    authorReference: Optional[Reference] = None
    time: Optional[Union[str, date, datetime]] = None


class Money(FhirBaseModel):
    value: Optional[Union[int, float]] = None
    currency: Optional[str] = None


class TimingRepeat(FhirBaseModel):
    boundsDuration: Optional[Quantity] = None
    boundsRange: Optional[Range] = None
    boundsPeriod: Optional[Period] = None
    frequency: Optional[int] = None
    frequencyMax: Optional[int] = None
    period: Optional[Union[int, float]] = None
    periodMax: Optional[Union[int, float]] = None
    periodUnit: Optional[str] = None
    duration: Optional[Union[int, float]] = None
    durationMax: Optional[Union[int, float]] = None
    durationUnit: Optional[str] = None
    offset: Optional[int] = None
    when: Optional[List[str]] = None
    dayOfWeek: Optional[List[str]] = None
    timeOfDay: Optional[List[str]] = None
    count: Optional[int] = None
    countMax: Optional[int] = None


class Timing(FhirBaseModel):
    code: Optional[CodeableConcept] = None
    repeat: Optional[TimingRepeat] = None
    event: Optional[List[Union[str, date, datetime]]] = None
