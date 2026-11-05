import email.message
import http.client
import io
import re
import socket
import ssl
from urllib.request import HTTPSHandler, Request, addinfourl

import pytest

from fixfirst.enrich.fetcher import (
    OVERALL_DEADLINE_SECONDS,
    SOCKET_TIMEOUT_SECONDS,
    UrllibFetcher,
    build_secure_opener,
    build_tls_context,
    user_agent,
)
from fixfirst.errors import EnrichmentError

URL = "https://feed.example.com/data.json"


class FakeHttps(HTTPSHandler):
    """Answers https requests in memory, but keeps the rest of the real opener chain."""

    def __init__(
        self,
        body: bytes = b"{}",
        status: int = 200,
        headers: dict[str, str] | None = None,
        error: Exception | None = None,
    ) -> None:
        super().__init__()
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.error = error
        self.requests: list[Request] = []
        self.timeouts: list[float | None] = []

    def https_open(self, req: Request) -> addinfourl:
        self.requests.append(req)
        self.timeouts.append(req.timeout)
        if self.error is not None:
            raise self.error
        message = email.message.Message()
        for name, value in self.headers.items():
            message[name] = value
        response = addinfourl(io.BytesIO(self.body), message, req.full_url, self.status)
        response.msg = "fake"
        return response


def fetcher_for(handler: FakeHttps) -> UrllibFetcher:
    return UrllibFetcher(build_secure_opener(handler))


def test_tests_cannot_reach_the_network() -> None:
    with pytest.raises(AssertionError, match="offline"):
        socket.create_connection(("example.com", 443))


def test_tls_context_verifies_certificates_and_host_names() -> None:
    context = build_tls_context()

    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_default_opener_uses_a_verifying_tls_handler() -> None:
    handlers = [h for h in build_secure_opener().handlers if isinstance(h, HTTPSHandler)]

    assert len(handlers) == 1
    assert handlers[0]._context.verify_mode is ssl.CERT_REQUIRED


def test_successful_fetch_returns_the_body_and_sets_headers_and_timeout() -> None:
    handler = FakeHttps(b'{"ok": true}')

    assert fetcher_for(handler).fetch(URL, 100) == b'{"ok": true}'

    request = handler.requests[0]
    assert request.get_header("User-agent") == user_agent()
    assert request.get_header("Accept-encoding") == "identity"
    assert handler.timeouts == [SOCKET_TIMEOUT_SECONDS]


def test_user_agent_identifies_only_the_tool() -> None:
    assert re.fullmatch(r"fixfirst/[0-9A-Za-z.+-]+", user_agent())


@pytest.mark.parametrize(
    "url",
    [
        "http://feed.example.com/data.json",
        "file:///etc/passwd",
        "ftp://feed.example.com/data.json",
        "HTTP://feed.example.com/data.json",
    ],
)
def test_only_https_is_allowed(url: str) -> None:
    handler = FakeHttps()

    with pytest.raises(EnrichmentError, match="not https"):
        fetcher_for(handler).fetch(url, 100)
    assert handler.requests == []


@pytest.mark.parametrize("target", ["https://other.example.com/", "http://feed.example.com/"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_refused(status: int, target: str) -> None:
    handler = FakeHttps(status=status, headers={"Location": target})

    with pytest.raises(EnrichmentError, match="HTTPError"):
        fetcher_for(handler).fetch(URL, 100)
    assert len(handler.requests) == 1


@pytest.mark.parametrize("status", [404, 429, 500, 503])
def test_error_statuses_fail(status: int) -> None:
    with pytest.raises(EnrichmentError, match="HTTPError"):
        fetcher_for(FakeHttps(status=status)).fetch(URL, 100)


def test_other_success_statuses_fail() -> None:
    with pytest.raises(EnrichmentError, match="unexpected HTTP status 204"):
        fetcher_for(FakeHttps(status=204)).fetch(URL, 100)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(TimeoutError(), id="timeout"),
        pytest.param(ssl.SSLCertVerificationError(), id="bad-certificate"),
        pytest.param(ConnectionResetError(), id="connection-reset"),
        pytest.param(http.client.IncompleteRead(b""), id="truncated-body"),
    ],
)
def test_transport_failures_become_enrichment_errors(error: Exception) -> None:
    with pytest.raises(EnrichmentError, match="request failed"):
        fetcher_for(FakeHttps(error=error)).fetch(URL, 100)


def test_response_at_the_limit_is_accepted_and_above_it_refused() -> None:
    body = b"x" * 1000

    assert fetcher_for(FakeHttps(body)).fetch(URL, 1000) == body
    with pytest.raises(EnrichmentError, match="byte limit"):
        fetcher_for(FakeHttps(body)).fetch(URL, 999)


def test_slow_response_hits_the_overall_deadline() -> None:
    times = iter([0.0, OVERALL_DEADLINE_SECONDS + 1])
    fetcher = UrllibFetcher(build_secure_opener(FakeHttps(b"x" * 10)), clock=lambda: next(times))

    with pytest.raises(EnrichmentError, match="took too long"):
        fetcher.fetch(URL, 100)


def test_errors_do_not_echo_response_content() -> None:
    handler = FakeHttps(b"SENTINEL" * 100, status=500)

    with pytest.raises(EnrichmentError) as excinfo:
        fetcher_for(handler).fetch(URL, 100)

    assert "SENTINEL" not in str(excinfo.value)
