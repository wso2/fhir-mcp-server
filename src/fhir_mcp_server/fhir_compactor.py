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
Token-efficient compaction of FHIR General-Purpose Data Types.

Each type is detected with a lightweight key-presence guard, then confirmed
via Pydantic model_validate. The resulting typed object is used by the
compactor to produce a short, human-readable string.
"""

import base64
from typing import Any, Dict, List

from .fhir_complex_data_types import (
    Address,
    Annotation,
    Attachment,
    CodeableConcept,
    Coding,
    ContactPoint,
    HumanName,
    Identifier,
    Money,
    Period,
    Quantity,
    Range,
    Ratio,
    Timing,
)
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# EventTiming code → human-readable label (R4 value set, static)
# https://hl7.org/fhir/R4/valueset-event-timing.html
# ---------------------------------------------------------------------------
_EVENT_TIMING: Dict[str, str] = {
    "MORN": "morning", "MORN.early": "early morning", "MORN.late": "late morning",
    "NOON": "noon",
    "AFT": "afternoon", "AFT.early": "early afternoon", "AFT.late": "late afternoon",
    "EVE": "evening", "EVE.early": "early evening", "EVE.late": "late evening",
    "NIGHT": "night", "PHS": "after sleep",
    "HS": "before sleep", "WAKE": "upon waking",
    "C": "with meal", "CM": "at breakfast", "CD": "at lunch", "CV": "at dinner",
    "AC": "before meal", "ACM": "before breakfast", "ACD": "before lunch", "ACV": "before dinner",
    "PC": "after meal", "PCM": "after breakfast", "PCD": "after lunch", "PCV": "after dinner",
}


# ---------------------------------------------------------------------------
# Compactors — operate on validated Pydantic model objects
# ---------------------------------------------------------------------------

def _fmt_quantity(v: Quantity) -> str:
    """Shared helper for Quantity, Range, and Ratio. E.g. {"value": 40000, "comparator": ">", "unit": "mcg/L"} -> ">40000 mcg/L"."""
    value_s = f"{float(v.value):g}" if v.value is not None else ""
    if v.comparator and value_s:
        value_s = f"{v.comparator}{value_s}"
    unit = v.unit or v.code
    if unit and value_s:
        return f"{value_s} {unit}"
    return value_s or unit or ""


def _compact_codeable_concept(v: CodeableConcept) -> str:
    """Compact a CodeableConcept: prefers text, then display+code, then system|code."""
    # {"coding": [..., "display": "Body Height"}], "text": "Body Height"} -> "Body Height"
    # {"coding": [{"system": "...", "code": "8302-2", "display": "Body Height"}]}  -> "Body Height (8302-2)"
    # {"coding": [{"system": "http://loinc.org", "code": "8302-2"}]}               -> "http://loinc.org|8302-2"
    if v.text:
        return v.text
    if v.coding:
        first = v.coding[0]
        if first.display:
            return f"{first.display} ({first.code})" if first.code else first.display
        if first.system and first.code:
            return f"{first.system}|{first.code}"
        if first.code:
            return first.code
    return ""


def _compact_coding(v: Coding) -> str:
    """Compact a Coding: prefers display+code, then system|code, then code alone."""
    # {"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"} -> "Body Height (8302-2)"
    # {"system": "http://loinc.org", "code": "8302-2"}                            -> "http://loinc.org|8302-2"
    # {"system": "http://loinc.org", "display": "Body Height"}                     -> "Body Height"
    if v.display:
        return f"{v.display} ({v.code})" if v.code else v.display
    if v.system and v.code:
        return f"{v.system}|{v.code}"
    return v.code or (str(v.system) if v.system else "")


def _compact_quantity(v: Quantity) -> str:
    """Compact a Quantity value. Also handles constrained subtypes Age, Count, Distance, Duration, MoneyQuantity, SimpleQuantity."""
    # {"value": 7.2, "unit": "mmol/L"}                      -> "7.2 mmol/L"
    # {"value": 5.0, "comparator": ">=", "unit": "mg/dL"}   -> ">=5 mg/dL"
    return _fmt_quantity(v)


def _compact_range(v: Range) -> str:
    """Compact a Range to "low – high", or just low/high if one bound is absent."""
    # {"low": {"value": 3.5, "unit": "mmol/L"}, "high": {"value": 5.5, "unit": "mmol/L"}} -> "3.5 mmol/L – 5.5 mmol/L"
    low_s = _fmt_quantity(v.low) if v.low else ""
    high_s = _fmt_quantity(v.high) if v.high else ""
    return f"{low_s} – {high_s}" if low_s and high_s else low_s or high_s


def _compact_ratio(v: Ratio) -> str:
    """Compact a Ratio to "numerator/denominator"; returns empty string if either side is absent."""
    # {"numerator": {"value": 1, "unit": "mg"}, "denominator": {"value": 10, "unit": "mL"}} -> "1 mg/10 mL"
    if not v.numerator or not v.denominator:
        return ""
    return f"{_fmt_quantity(v.numerator)}/{_fmt_quantity(v.denominator)}"


def _compact_period(v: Period) -> str:
    """Compact a Period to "start – end", "from start", or "until end"."""
    # {"start": "2024-01-01", "end": "2024-06-30"} -> "2024-01-01 – 2024-06-30"
    # {"start": "2024-01-01"}                       -> "from 2024-01-01"
    # {"end": "2024-06-30"}                         -> "until 2024-06-30"
    start = str(v.start) if v.start else ""
    end = str(v.end) if v.end else ""
    if start and end:
        return f"{start} – {end}"
    return f"from {start}" if start else f"until {end}" if end else ""


def _compact_human_name(v: HumanName) -> str:
    """Compact a HumanName to "prefix given family suffix"; appends use unless official."""
    # {"use": "official", "family": "Smith", "given": ["John"], "prefix": ["Dr."]} -> "Dr. John Smith"
    # {"use": "nickname", "given": ["Johnny"]}                                      -> "Johnny (nickname)"
    if v.text:
        return v.text
    parts: List[str] = [*(v.prefix or []), *(v.given or [])]
    if v.family:
        parts.append(v.family)
    parts.extend(v.suffix or [])
    result = " ".join(parts)
    return f"{result} ({v.use})" if v.use and v.use != "official" else result


def _compact_address(v: Address) -> str:
    """Compact an Address to a single line; appends use and type when present."""
    # {"line": ["123 Main St"], "city": "Boston", "district": "Suffolk", "state": "MA", "postalCode": "02101", "country": "US"} -> "123 Main St, Boston Suffolk MA 02101, US"
    # {"text": "123 Main St, Boston MA 02101"}                                                                                    -> "123 Main St, Boston MA 02101"
    # {"use": "home", "type": "postal", "line": ["123 Main St"], "city": "Boston"}                                               -> "123 Main St, Boston (home, postal)"
    if v.text:
        return v.text
    parts: List[str] = []
    if v.line:
        parts.append(", ".join(v.line))
    location = " ".join(filter(None, [v.city or "", v.district or "", v.state or "", v.postalCode or ""]))
    if location:
        parts.append(location)
    if v.country:
        parts.append(v.country)
    result = ", ".join(parts)
    qualifiers = ", ".join(filter(None, [v.use or "", v.type or ""]))
    return f"{result} ({qualifiers})" if qualifiers else result


def _compact_contact_point(v: ContactPoint) -> str:
    """Compact a ContactPoint to "system: value (use) #rank"."""
    # {"system": "phone", "value": "555-1234", "use": "home"}          -> "phone: 555-1234 (home)"
    # {"system": "email", "value": "john@example.com"}                  -> "email: john@example.com"
    # {"system": "phone", "value": "555-1234", "use": "home", "rank": 1} -> "phone: 555-1234 (home) #1"
    system = v.system or ""
    value = v.value or ""
    result = f"{system}: {value}" if system else value
    if v.use:
        result = f"{result} ({v.use})"
    if v.rank is not None:
        result = f"{result} #{v.rank}"
    return result


def _compact_identifier(v: Identifier) -> str:
    """Compact an Identifier to "type: system|value [use]"."""
    # {"system": "http://hospital.org/mrn", "value": "MRN123", "use": "official"}                    -> "http://hospital.org/mrn|MRN123 [official]"
    # {"type": {"text": "MRN"}, "system": "http://hospital.org/mrn", "value": "MRN123"}              -> "MRN: http://hospital.org/mrn|MRN123"
    system = str(v.system) if v.system else ""
    value = v.value or ""
    result = f"{system}|{value}" if system and value else value or system
    if v.use:
        result = f"{result} [{v.use}]"
    if v.type:
        type_label = _compact_codeable_concept(v.type)
        if type_label:
            result = f"{type_label}: {result}"
    return result


def _compact_attachment(v: Attachment) -> str:
    """Compact an Attachment: title, url, decoded text, or base64 data URI in priority order."""
    # {"title": "Discharge Summary", "contentType": "application/pdf"} -> "Discharge Summary (application/pdf)"
    # {"url": "http://example.com/image.png", "contentType": "image/png"} -> "http://example.com/image.png"
    # {"data": "<base64>", "contentType": "text/plain"} -> decoded text
    # {"data": "<base64>", "contentType": "application/pdf"} -> "data:application/pdf;base64,<data>"
    if v.title:
        return f"{v.title} ({v.contentType})" if v.contentType else v.title
    if v.url:
        return str(v.url)
    if v.data:
        ct = v.contentType or ""
        if ct.startswith("text/"):  # decode to readable text; binary stays as data URI
            return v.data.decode("utf-8", errors="replace")
        b64 = base64.b64encode(v.data).decode("ascii")
        return f"data:{ct};base64,{b64}" if ct else b64
    return v.contentType or "[attachment]"


def _compact_timing(v: Timing) -> str:
    """Compact a Timing schedule: code abbreviation, structured repeat, or event list."""
    # {"code": {"text": "Take in the morning on weekends"}}                                              -> "Take in the morning on weekends"
    # {"code": {"coding": [{"code": "BID"}]}}                                                           -> "BID"
    # {"repeat": {"frequency": 3, "period": 1, "periodUnit": "d"}}                                      -> "3x/day"
    # {"repeat": {"frequency": 1, "period": 8, "periodUnit": "h"}}                                      -> "every 8h"
    # {"repeat": {"duration": 5, "durationUnit": "min", "when": ["AC"], "offset": 10}}                  -> "for 5min, 10min before meal"
    if v.code:
        code_str = _compact_codeable_concept(v.code)
        if code_str:
            return code_str

    if v.repeat:
        r = v.repeat
        parts: List[str] = []

        if r.period is not None or r.frequency is not None:
            unit = r.periodUnit or ""
            _UNIT_NAMES = {"d": "day", "wk": "wk", "mo": "mo", "h": "h", "min": "min", "s": "s", "a": "yr"}
            freq = r.frequency
            freq_max = r.frequencyMax
            freq_s = f"{freq}-{freq_max}" if freq_max else str(freq) if freq is not None else "1"
            if r.period == 1 and not r.periodMax:
                unit_name = _UNIT_NAMES.get(unit, unit)
                parts.append(f"{freq_s}x/{unit_name}")
            else:
                period_s = f"{r.period}-{r.periodMax}{unit}" if r.periodMax else f"{r.period}{unit}"
                if freq is not None and (freq > 1 or freq_max):
                    parts.append(f"{freq_s}x/{period_s}")
                else:
                    parts.append(f"every {period_s}")

        if r.duration is not None:
            dur_unit = r.durationUnit or ""
            dur_s = f"{r.duration}-{r.durationMax}{dur_unit}" if r.durationMax else f"{r.duration}{dur_unit}"
            if r.offset is not None and r.when:
                when_s = "/".join(_EVENT_TIMING.get(w, w) for w in r.when)
                parts.append(f"for {dur_s}, {r.offset}min {when_s}")
            else:
                parts.append(f"for {dur_s}")

        if r.dayOfWeek:
            parts.append("on " + "/".join(d.capitalize() for d in r.dayOfWeek))

        if r.timeOfDay:
            parts.append("at " + ", ".join(str(t)[:5] for t in r.timeOfDay))

        if r.when and not (r.duration is not None and r.offset is not None):
            when_s = "/".join(_EVENT_TIMING.get(w, w) for w in r.when)
            parts.append(f"{r.offset}min {when_s}" if r.offset is not None else when_s)

        if r.count is not None:
            count_s = f"{r.count}-{r.countMax}" if r.countMax else str(r.count)
            parts.append(f"{count_s} time" if r.count == 1 and not r.countMax else f"{count_s} times")

        if r.boundsDuration is not None:
            bd = r.boundsDuration
            bd_s = f"{bd.value:g}{bd.unit or bd.code or ''}" if bd.value is not None else bd.unit or bd.code or ""
            parts.append(f"for {bd_s}")
        elif r.boundsRange is not None:
            parts.append(f"for {_compact_range(r.boundsRange)}")
        elif r.boundsPeriod is not None:
            bounds_p = _compact_period(r.boundsPeriod)
            if bounds_p:
                parts.append(bounds_p)

        if parts:
            return " ".join(parts)

    if v.event:
        return ", ".join((e.isoformat() if hasattr(e, "isoformat") else str(e)).replace("+00:00", "Z") for e in v.event)

    return ""


def _compact_annotation(v: Annotation) -> str:
    """Compact an Annotation to "text (author, time)"; author/time included per spec warning on modifying information."""
    # {"text": "Patient was fasting", "time": "2024-01-01T09:00:00Z"}                          -> "Patient was fasting (2024-01-01T09:00:00Z)"
    # {"text": "Patient was fasting", "authorString": "Dr. Smith", "time": "2024-01-01"}       -> "Patient was fasting (Dr. Smith, 2024-01-01)"
    meta: List[str] = []
    if v.authorString:
        meta.append(v.authorString)
    elif v.authorReference and v.authorReference.reference:
        meta.append(v.authorReference.reference)
    if v.time:
        t = v.time.isoformat() if hasattr(v.time, "isoformat") else str(v.time)
        meta.append(t.replace("+00:00", "Z"))
    text = v.text or ""
    return f"{text} ({', '.join(meta)})" if meta else text


def _compact_money(v: Money) -> str:
    """Compact a Money value to "amount currency"."""
    # {"value": 49.99, "currency": "USD"} -> "49.99 USD"
    value = f"{float(v.value):g}" if v.value is not None else ""
    currency = v.currency or ""
    return f"{value} {currency}".strip()


def compact_resource(data: Any) -> Any:
    """Recursively compact FHIR General-Purpose Data Types in a FHIR response.

    Handled: Coding, CodeableConcept, Quantity (+ subtypes Age/Count/Distance/Duration/
    MoneyQuantity/SimpleQuantity), Range, Ratio, Period, HumanName, Address, ContactPoint,
    Identifier, Attachment, Annotation, Money, Timing.

    Not handled (returned as-is):
    - SampledData: waveform/time-series data, no meaningful compact text form.
    - Signature: digital signature bytes, not human-readable.
    """

    if isinstance(data, list):  # FHIRPath returns lists — compact each matched value
        return [compact_resource(item) for item in data]
    if not isinstance(data, dict):  # primitive (string, number, bool) — nothing to compact
        return data

    for fhir_type, compactor in [
        (Ratio,           _compact_ratio),
        (Range,           _compact_range),
        (Money,           _compact_money),
        (Annotation,      _compact_annotation),
        (Period,          _compact_period),
        (HumanName,       _compact_human_name),
        (Address,         _compact_address),
        (Coding,          _compact_coding),
        (CodeableConcept, _compact_codeable_concept),
        (Quantity,        _compact_quantity),
        (Attachment,      _compact_attachment),
        (ContactPoint,    _compact_contact_point),
        (Identifier,      _compact_identifier),
        (Timing,          _compact_timing),
    ]:
        try:
            result = compactor(fhir_type.model_validate(data))
            return result if result else data
        except ValidationError:
            continue

    return {k: compact_resource(val) for k, val in data.items()}
