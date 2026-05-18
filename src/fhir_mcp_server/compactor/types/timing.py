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
from typing import Dict, List, Optional, Union


from .codeable_concept import CodeableConcept
from .timing_repeat import TimingRepeat
from .base import FhirTypesBaseModel


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EventTiming code → human-readable label (R4 value set, static)
# https://hl7.org/fhir/R4/valueset-event-timing.html
# ---------------------------------------------------------------------------
_EVENT_TIMING: Dict[str, str] = {
    "MORN": "morning",
    "MORN.early": "early morning",
    "MORN.late": "late morning",
    "NOON": "noon",
    "AFT": "afternoon",
    "AFT.early": "early afternoon",
    "AFT.late": "late afternoon",
    "EVE": "evening",
    "EVE.early": "early evening",
    "EVE.late": "late evening",
    "NIGHT": "night",
    "PHS": "after sleep",
    "HS": "before sleep",
    "WAKE": "upon waking",
    "C": "with meal",
    "CM": "at breakfast",
    "CD": "at lunch",
    "CV": "at dinner",
    "AC": "before meal",
    "ACM": "before breakfast",
    "ACD": "before lunch",
    "ACV": "before dinner",
    "PC": "after meal",
    "PCM": "after breakfast",
    "PCD": "after lunch",
    "PCV": "after dinner",
}
_UNIT_NAMES = {
    "d": "day",
    "wk": "wk",
    "mo": "mo",
    "h": "h",
    "min": "min",
    "s": "s",
    "a": "yr",
}


class Timing(FhirTypesBaseModel):
    code: Optional[CodeableConcept] = None
    repeat: Optional[TimingRepeat] = None
    event: Optional[List[Union[str, date, datetime]]] = None

    def compact(self) -> str:
        """Compact a Timing schedule: code abbreviation, structured repeat, or event list."""
        # {"code": {"text": "Take in the morning on weekends"}}                                              -> "Take in the morning on weekends"
        # {"code": {"coding": [{"code": "BID"}]}}                                                           -> "BID"
        # {"repeat": {"frequency": 3, "period": 1, "periodUnit": "d"}}                                      -> "3x/day"
        # {"repeat": {"frequency": 1, "period": 8, "periodUnit": "h"}}                                      -> "every 8h"
        # {"repeat": {"duration": 5, "durationUnit": "min", "when": ["AC"], "offset": 10}}                  -> "for 5min, 10min before meal"
        logger.debug(f"Compacting Timing: {self.model_dump_json()}")
        if self.code:
            code_str = self.code.compact()
            if code_str:
                logger.debug(f"Compacted Timing using code: '{code_str}'")
                return code_str

        if self.repeat:
            r = self.repeat
            parts: List[str] = []

            if r.period is not None or r.frequency is not None:
                unit = r.periodUnit or ""

                freq = r.frequency
                freq_max = r.frequencyMax
                freq_s = (
                    f"{freq}-{freq_max}"
                    if freq_max
                    else str(freq)
                    if freq is not None
                    else "1"
                )
                if r.period == 1 and not r.periodMax:
                    unit_name = _UNIT_NAMES.get(unit, unit)
                    parts.append(f"{freq_s}x/{unit_name}")
                else:
                    period_s = (
                        f"{r.period}-{r.periodMax}{unit}"
                        if r.periodMax
                        else f"{r.period}{unit}"
                    )
                    if freq is not None and (freq > 1 or freq_max):
                        parts.append(f"{freq_s}x/{period_s}")
                    else:
                        parts.append(f"every {period_s}")

            if r.duration is not None:
                dur_unit = r.durationUnit or ""
                dur_s = (
                    f"{r.duration}-{r.durationMax}{dur_unit}"
                    if r.durationMax
                    else f"{r.duration}{dur_unit}"
                )
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
                parts.append(
                    f"{r.offset}min {when_s}" if r.offset is not None else when_s
                )

            if r.count is not None:
                count_s = f"{r.count}-{r.countMax}" if r.countMax else str(r.count)
                parts.append(
                    f"{count_s} time"
                    if r.count == 1 and not r.countMax
                    else f"{count_s} times"
                )

            if r.boundsDuration is not None:
                bd = r.boundsDuration
                bd_s = (
                    f"{bd.value:g}{bd.unit or bd.code or ''}"
                    if bd.value is not None
                    else bd.unit or bd.code or ""
                )
                parts.append(f"for {bd_s}")
            elif r.boundsRange is not None:
                parts.append(f"for {r.boundsRange.compact()}")
            elif r.boundsPeriod is not None:
                bounds_p = r.boundsPeriod.compact()
                if bounds_p:
                    parts.append(bounds_p)

            if parts:
                compacted = " ".join(parts)
                logger.debug(f"Compacted Timing using repeat: '{compacted}'")
                return compacted

        if self.event:
            compacted = ", ".join(
                (e.isoformat() if hasattr(e, "isoformat") else str(e)).replace(
                    "+00:00", "Z"
                )
                for e in self.event
            )
            logger.debug(f"Compacted Timing using event list: '{compacted}'")
            return compacted

        logger.debug("Timing has no code, repeat, or event, returning empty string")
        return ""
