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

from ..types.complex_types import Attachment


import base64

logger = logging.getLogger(__name__)


def compact(attachment: Attachment) -> str:
    """Compact an Attachment: title, url, decoded text, or base64 data URI in priority order."""
    # {"title": "Discharge Summary", "contentType": "application/pdf"} -> "Discharge Summary (application/pdf)"
    # {"url": "http://example.com/image.png", "contentType": "image/png"} -> "http://example.com/image.png"
    # {"data": "<base64>", "contentType": "text/plain"} -> decoded text
    # {"data": "<base64>", "contentType": "application/pdf"} -> "data:application/pdf;base64,<data>"
    logger.debug(f"Compacting attachment: {attachment}")
    if attachment.title:
        compacted = f"{attachment.title} ({attachment.contentType})" if attachment.contentType else attachment.title
        logger.debug(f"Compacted attachment using title: '{compacted}'")
        return compacted
    if attachment.url:
        logger.debug(f"Compacted attachment using url: '{attachment.url}'")
        return str(attachment.url)
    if attachment.data:
        ct = attachment.contentType or ""
        data = attachment.data
        if isinstance(data, str):
            try:
                data = base64.b64decode(data, validate=True)
            except Exception:
                data = data.encode("utf-8")
        if ct.startswith("text/"):
            compacted = data.decode("utf-8", errors="replace")
            logger.debug(f"Compacted attachment by decoding text/{ct} data")
            return compacted
        b64 = base64.b64encode(data).decode("ascii")
        compacted = f"data:{ct};base64,{b64}" if ct else b64
        logger.debug(f"Compacted attachment as base64 data URI with contentType '{ct}'")
        return compacted
    compacted = attachment.contentType or "[attachment]"
    logger.debug(f"No title/url/data, falling back to: '{compacted}'")
    return compacted
