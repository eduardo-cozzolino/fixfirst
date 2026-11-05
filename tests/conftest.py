"""Shared test setup."""

import socket
from typing import NoReturn

import pytest


def _refuse_network(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("tests must stay offline")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that tries to reach the network, instead of letting it pass by accident."""
    monkeypatch.setattr(socket.socket, "connect", _refuse_network)
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse_network)
    monkeypatch.setattr(socket, "getaddrinfo", _refuse_network)
