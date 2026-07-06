"""Network egress allowlist (criterion 8: assert via allowlist in code)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from runworthy.engine import scan
from runworthy.net import NETWORK_ALLOWLIST, EgressBlocked, no_egress_guard

FIXTURES = Path(__file__).parent / "fixtures"


def test_allowlist_contains_osv():
    assert "api.osv.dev" in NETWORK_ALLOWLIST


def test_guard_blocks_non_allowlisted_host():
    with no_egress_guard():
        with pytest.raises(EgressBlocked):
            socket.getaddrinfo("evil.example.com", 443)


def test_guard_allows_allowlisted_host():
    with no_egress_guard():
        try:
            socket.getaddrinfo("api.osv.dev", 443)
        except EgressBlocked:
            pytest.fail("allowlisted host was blocked")
        except socket.gaierror:
            pass  # offline is fine — we only assert it wasn't blocked


def test_guard_allows_loopback():
    with no_egress_guard():
        socket.getaddrinfo("localhost", 80)


def test_engine_core_makes_no_rogue_egress():
    """The no-agent early-exit path touches no network from Python at all."""
    with no_egress_guard():
        report = scan(str(FIXTURES / "noagent_repo"), generated_at="2026-07-05T00:00:00Z")
    assert report.verdict.value == "PROVISIONAL"
    assert report.findings == []
