# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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

import base64
from datetime import date, datetime
from typing import ClassVar, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


_CONTACT_POINT_SYSTEMS = {"phone", "fax", "email", "pager", "url", "sms", "other"}


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

    @model_validator(mode="after")
    def _require_system_with_code(self):
        if self.code and not self.system:
            raise ValueError("Quantity.system is required when code is present")
        return self


class Range(FhirBaseModel):
    low: Optional[Quantity] = None
    high: Optional[Quantity] = None

    @model_validator(mode="after")
    def _require_low_lt_high(self):
        if self.low and self.high:
            low_value = self.low.value
            high_value = self.high.value
            if low_value is not None and high_value is not None and low_value >= high_value:
                raise ValueError("Range.low must be lower than Range.high")
        return self


class Ratio(FhirBaseModel):
    numerator: Optional[Quantity] = None
    denominator: Optional[Quantity] = None
    # FHIR requires both or neither, but relaxed here so partial Ratios still
    # match this type and _compact_ratio returns "" to signal "return raw".
    # Adding validation here would cause partial Ratios to fall through to
    # generic dict recursion, producing half-compacted dicts like {"numerator": "1 mg"}.



class Period(FhirBaseModel):
    start: Optional[Union[str, date, datetime]] = None
    end: Optional[Union[str, date, datetime]] = None

    @model_validator(mode="after")
    def _require_start_lt_end(self):
        if self.start and self.end:
            def _to_dt(v: Union[str, date, datetime]) -> datetime:
                if isinstance(v, datetime):
                    return v
                if isinstance(v, date):
                    return datetime(v.year, v.month, v.day)
                return datetime.fromisoformat(str(v))
            try:
                if _to_dt(self.start) > _to_dt(self.end):
                    raise ValueError("Period.start must not be later than Period.end")
            except ValueError as exc:
                if "Period.start" in str(exc):
                    raise
        return self


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
    system: Optional[str] = None
    value: Optional[str] = None
    use: Optional[str] = None
    rank: Optional[int] = None
    period: Optional[Period] = None

    @model_validator(mode="after")
    def _validate(self):
        if self.value and not self.system:
            raise ValueError("ContactPoint.system is required when value is present")
        if self.system and self.system not in _CONTACT_POINT_SYSTEMS:
            raise ValueError(f"ContactPoint.system must be one of {_CONTACT_POINT_SYSTEMS}")
        return self


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

    @field_validator("hash", mode="before")
    @classmethod
    def _decode_base64_hash(cls, value):
        if value is None or isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except Exception:
                return value.encode("utf-8")
        return value

    @field_validator("data", mode="before")
    @classmethod
    def _decode_base64_data(cls, value):
        if value is None or isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except Exception:
                return value.encode("utf-8")
        return value

    @model_validator(mode="after")
    def _validate(self):
        if self.data is not None and not self.contentType:
            raise ValueError("Attachment.contentType is required when data is present")
        # Reject extension-shaped dicts: url-only with no Attachment content fields
        content_fields = [self.contentType, self.data, self.title, self.size, self.hash, self.language, self.creation]
        if self.url and not any(f is not None for f in content_fields):
            raise ValueError("Attachment requires at least one content field alongside url")
        return self


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

    @model_validator(mode="after")
    def _validate_repeat_rules(self):
        if self.duration is not None:
            if self.duration < 0:
                raise ValueError("Timing.repeat.duration must be non-negative")
            if not self.durationUnit:
                raise ValueError("Timing.repeat.durationUnit is required when duration is present")
        if self.period is not None:
            if self.period < 0:
                raise ValueError("Timing.repeat.period must be non-negative")
            if not self.periodUnit:
                raise ValueError("Timing.repeat.periodUnit is required when period is present")
        if self.periodMax is not None and self.period is None:
            raise ValueError("Timing.repeat.period is required when periodMax is present")
        if self.durationMax is not None and self.duration is None:
            raise ValueError("Timing.repeat.duration is required when durationMax is present")
        if self.countMax is not None and self.count is None:
            raise ValueError("Timing.repeat.count is required when countMax is present")
        if self.timeOfDay and self.when:
            raise ValueError("Timing.repeat.timeOfDay cannot be used with when")
        if self.offset is not None:
            if not self.when:
                raise ValueError("Timing.repeat.when is required when offset is present")
            disallowed = {"C", "CM", "CD", "CV"}
            if any(code in disallowed for code in self.when or []):
                raise ValueError("Timing.repeat.when cannot include C, CM, CD, or CV when offset is present")
        return self


class Timing(FhirBaseModel):
    code: Optional[CodeableConcept] = None
    repeat: Optional[TimingRepeat] = None
    event: Optional[List[Union[str, date, datetime]]] = None

