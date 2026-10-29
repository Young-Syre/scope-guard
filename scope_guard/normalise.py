"""Normalisation of hosts and URL paths.

Every comparison in scope-guard happens on normalised values, so that the
cosmetic differences between how a host or path is written cannot change a
verdict. The two public entry points are :func:`normalise_host` and
:func:`normalise_path`.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import unquote

from .errors import ScopeFileError

__all__ = [
    "normalise_host",
    "normalise_path",
    "path_segments_to_str",
    "parse_ip",
    "parse_network",
    "host_labels",
    "is_ip_literal",
]


def normalise_host(host: str, *, context: str = "host") -> str:
    """Return the canonical ASCII form of ``host``.

    Applied, in order:

    * surrounding whitespace is stripped;
    * a single trailing dot (the fully-qualified form, ``example.com.``) is
      removed, so it compares equal to ``example.com``;
    * square brackets around an IPv6 literal are removed;
    * IP literals are canonicalised through :mod:`ipaddress` so that
      ``2001:DB8::0:1`` and ``2001:db8::1`` compare equal;
    * anything else is IDNA-encoded to ASCII and lowercased, so that
      ``EXAMPLE.com``, ``bücher.example.com`` and
      ``xn--bcher-kva.example.com`` all converge.

    Raises :class:`ScopeFileError` when the host cannot be normalised at all
    (an empty label, an over-long label, a stray ``*``). An unnormalisable
    host is always an authoring bug, never something to silently tolerate.
    """
    raw = host.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if raw.endswith(".") and not raw.endswith(".."):
        raw = raw[:-1]
    if not raw:
        raise ScopeFileError(f"empty {context}")
    if "*" in raw:
        raise ScopeFileError(
            f"{context} {host!r} contains '*'; use type = \"wildcard\" for "
            "wildcard entries"
        )
    if "/" in raw or "\\" in raw:
        raise ScopeFileError(f"{context} {host!r} contains a path separator")

    # An IP literal is canonicalised as an address, not as a domain name.
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass

    lowered = raw.lower()
    if lowered.isascii():
        _validate_ascii_host(lowered, host, context)
        return lowered
    try:
        return raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeFileError(f"{context} {host!r} is not a valid IDN: {exc}") from exc


def _validate_ascii_host(lowered: str, original: str, context: str) -> None:
    """Reject ASCII hosts the IDNA codec would also have rejected.

    The IDNA codec is only exercised for non-ASCII hosts, so the same
    structural rules are applied here by hand: no empty labels and no label
    longer than 63 bytes.
    """
    for label in lowered.split("."):
        if not label:
            raise ScopeFileError(f"{context} {original!r} has an empty label")
        if len(label) > 63:
            raise ScopeFileError(f"{context} {original!r} has a label over 63 bytes")


def host_labels(host: str) -> tuple[str, ...]:
    """Split a normalised host into its DNS labels."""
    return tuple(host.split(".")) if host else ()


def is_ip_literal(host: str) -> bool:
    """True when ``host`` is an IPv4 or IPv6 literal rather than a name."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def parse_ip(value: str, *, context: str = "ip") -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an IP literal, raising :class:`ScopeFileError` on failure."""
    raw = value.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ScopeFileError(f"{context} {value!r} is not a valid IP address") from exc


def parse_network(value: str, *, context: str = "cidr") -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a CIDR block, raising :class:`ScopeFileError` on failure.

    ``strict=False`` is deliberate: ``10.0.0.5/24`` is accepted and read as
    ``10.0.0.0/24``. Policy pages are written by people, and a host address
    with a prefix length is a common and unambiguous way to write a block.
    """
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ScopeFileError(f"{context} {value!r} is not a valid CIDR block") from exc


def normalise_path(path: str) -> tuple[str, ...]:
    """Reduce a URL path to a tuple of normalised, decoded segments.

    The order of operations matters and is deliberate:

    1. split on ``/`` **first**, so a percent-encoded separator (``%2F``)
       cannot invent a new segment boundary;
    2. percent-decode each segment;
    3. drop empty segments and ``.``;
    4. pop the previous segment for each ``..``.

    Dot segments are resolved *after* decoding, so ``/api/%2e%2e/admin``
    reduces to ``('admin',)`` exactly as ``/api/../admin`` does. RFC 3986
    would resolve dot segments before decoding and so would treat ``%2e%2e``
    as an ordinary segment, but the conservative reading is the correct one
    for an authorisation check: if a request could reach ``/admin`` on some
    server, the verdict should be the verdict for ``/admin``.

    ``..`` that would escape the root is discarded, matching how servers
    clamp traversal at the document root.
    """
    out: list[str] = []
    for raw_segment in path.split("/"):
        segment = unquote(raw_segment)
        if segment == "" or segment == ".":
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    return tuple(out)


def path_segments_to_str(segments: tuple[str, ...]) -> str:
    """Render normalised segments back into a readable path."""
    return "/" + "/".join(segments) if segments else "/"
