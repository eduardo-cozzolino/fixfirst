"""Threat intelligence enrichment from public sources."""

import re
from typing import Annotated

from pydantic import StringConstraints

# Vulnerability ids come from untrusted reports and end up in request URLs, so only this exact form
# is ever looked up. The length cap also keeps a crafted id from overflowing an EPSS request.
_CVE_ID_REGEX = r"CVE-[0-9]{4}-[0-9]{4,7}"
_CVE_ID = re.compile(_CVE_ID_REGEX)

CveId = Annotated[str, StringConstraints(strict=True, pattern=f"^{_CVE_ID_REGEX}$")]


def is_cve_id(value: str) -> bool:
    """Return whether a vulnerability id is a CVE id that can be looked up."""
    return _CVE_ID.fullmatch(value) is not None
