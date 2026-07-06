"""Network egress allowlist.

The core engine's own Python code makes **no** network calls except ``git``
(intake clone, run as a subprocess). Detectors that reach the network are
version-pinned subprocesses whose only remote is OSV.dev (spec §5, §6).

``no_egress_guard`` enforces the allowlist inside the *Python* process — it is
used by the test-suite to prove the engine core opens no un-allowlisted sockets
(criterion 8: "assert via allowlist in code, not promise"). Out-of-process tool
egress is documented and pinned, not socket-patchable from here.
"""

from __future__ import annotations

import socket
from contextlib import contextmanager
from collections.abc import Iterator, Iterable

#: Hosts the engine (and its pinned detectors) are permitted to reach.
NETWORK_ALLOWLIST: frozenset[str] = frozenset(
    {
        "osv.dev",
        "api.osv.dev",
        # git intake hosts (clone only)
        "github.com",
        "www.github.com",
        "codeload.github.com",
        "gitlab.com",
        "bitbucket.org",
    }
)


class EgressBlocked(RuntimeError):
    """Raised when code attempts to connect to a non-allowlisted host."""


def _host_allowed(host: str, allow: frozenset[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if host in allow:
        return True
    # allow subdomains of allowlisted apex domains
    return any(host == a or host.endswith("." + a) for a in allow)


@contextmanager
def no_egress_guard(extra_allowed: Iterable[str] = ()) -> Iterator[None]:
    """Within this block, any socket connect to a host outside the allowlist
    raises ``EgressBlocked``. Loopback is always permitted."""
    allow = NETWORK_ALLOWLIST | frozenset(h.lower() for h in extra_allowed)
    real_getaddrinfo = socket.getaddrinfo

    def guarded_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
        if host not in (None, "localhost", "127.0.0.1", "::1") and not _host_allowed(str(host), allow):
            raise EgressBlocked(f"blocked egress to non-allowlisted host: {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo  # type: ignore[assignment]
