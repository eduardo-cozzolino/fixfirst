"""HTTP access for enrichment, behind an interface that tests can replace."""

import http.client
import ssl
import time
from collections.abc import Callable
from email.message import Message
from importlib.metadata import PackageNotFoundError, version
from typing import IO, Protocol
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    Request,
    build_opener,
)

from fixfirst.errors import EnrichmentError

SOCKET_TIMEOUT_SECONDS = 30.0
OVERALL_DEADLINE_SECONDS = 120.0

_CHUNK_BYTES = 64 * 1024


class Fetcher(Protocol):
    """Retrieves the content of a URL."""

    def fetch(self, url: str, max_bytes: int) -> bytes:
        """Return the response body.

        Raises:
            EnrichmentError: The content cannot be retrieved or is larger than ``max_bytes``.
        """
        ...


class _RefuseRedirects(HTTPRedirectHandler):
    """Treat every redirect as an error, because following one could change host or downgrade TLS.

    The KEV and EPSS endpoints do not redirect.
    """

    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> Request | None:
        return None


def build_tls_context() -> ssl.SSLContext:
    """Return a TLS context that verifies certificates and host names."""
    return ssl.create_default_context()


def build_secure_opener(https_handler: HTTPSHandler | None = None) -> OpenerDirector:
    """Return an opener that verifies TLS and refuses redirects."""
    handler = https_handler or HTTPSHandler(context=build_tls_context())
    return build_opener(handler, _RefuseRedirects())


def user_agent() -> str:
    """Return the User-Agent header, which identifies the tool and nothing else."""
    try:
        return f"fixfirst/{version('fixfirst')}"
    except PackageNotFoundError:
        return "fixfirst/unknown"


class UrllibFetcher:
    """Fetches https URLs with timeouts and a response size limit."""

    def __init__(
        self,
        opener: OpenerDirector | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._opener = opener or build_secure_opener()
        self._clock = clock

    def fetch(self, url: str, max_bytes: int) -> bytes:
        """Return the response body of an https URL.

        Raises:
            EnrichmentError: The request fails, redirects, takes too long or returns too much.
        """
        parts = urlsplit(url)
        host = parts.hostname or "<no host>"
        if parts.scheme != "https":
            raise EnrichmentError(f"{host}: refusing a request that is not https")
        # The scheme is checked directly above, so file: and similar URLs cannot reach urllib.
        request = Request(  # noqa: S310
            url,
            headers={
                "User-Agent": user_agent(),
                "Accept": "application/json",
                # Asking for no compression means a small response cannot expand past the limit.
                "Accept-Encoding": "identity",
            },
        )
        try:
            with self._opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS) as response:
                status: int = response.status
                if status != http.client.OK:
                    raise EnrichmentError(f"{host}: unexpected HTTP status {status}")
                return self._read(response, host, max_bytes)
        except (OSError, http.client.HTTPException) as exc:
            # HTTPError, URLError, TimeoutError and ssl.SSLError are all OSError subclasses.
            raise EnrichmentError(f"{host}: request failed ({type(exc).__name__})") from exc

    def _read(self, response: http.client.HTTPResponse, host: str, max_bytes: int) -> bytes:
        # A socket timeout only limits each read, so a slow trickle needs its own deadline.
        deadline = self._clock() + OVERALL_DEADLINE_SECONDS
        chunks: list[bytes] = []
        total = 0
        while chunk := response.read(_CHUNK_BYTES):
            total += len(chunk)
            if total > max_bytes:
                raise EnrichmentError(f"{host}: response exceeds the {max_bytes} byte limit")
            if self._clock() > deadline:
                raise EnrichmentError(f"{host}: response took too long")
            chunks.append(chunk)
        return b"".join(chunks)
