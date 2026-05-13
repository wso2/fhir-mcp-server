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

from typing import List, Optional, Union

from .period import Period
from . import Quantity
from . import Range
from .base import FhirBaseModel


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
