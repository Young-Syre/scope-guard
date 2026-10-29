"""Parsing of the thing you are about to test into a matchable target.

A target is whatever you typed: a bare hostname, a URL, an IP address, a
mobile package identifier or a repository. :func:`parse_target` turns it into
a :class:`Target` with every component already normalised.

No DNS lookup, and no network traffic of any kind, happens here or anywhere
else in the decision path. A hostname stays a hostname; it is never resolved
to an address. That is why CIDR entries cannot decide a hostname target --
see :attr:`Target.kind` and the limitations section of the README.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .errors import TargetError
from .normalise import normalise_host, normalise_path, path_segments_to_str

__all__ = ["Target", "TargetKind", "parse_target", "TARGET_KINDS"]

#: Target kinds, matching the families a scope entry can constrain.
TARGET_KINDS = ("host", "ip", "android-package", "ios-bundle", "repo")

TargetKind = str

#: Schemes whose default port is well known, used to resolve an implicit port.
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

_EXPLICIT_PREFIXES = {
    "android:": "android-package",
    "ios:": "ios-bundle",
    "repo:": "repo",
}


@dataclass(frozen=True)
class Target:
    """A normalised target, ready to be matched against scope entries."""

    raw: str
    kind: TargetKind
    host: str | None = None
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    scheme: str | None = None
    port: int | None = None
    #: ``None`` means "no path component was supplied", which is different
    #: from ``()`` meaning "the root path". Path entries are not evaluated
    #: against a target with no path at all.
    path: tuple[str, ...] | None = None
    identifier: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def addresses(self) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        """Every address form of this target that CIDR membership may use.

        An IPv4-mapped IPv6 address such as ``::ffff:192.0.2.5`` is also
        offered as ``192.0.2.5``, and a bare IPv4 address is also offered in
        its mapped IPv6 form, so that a target matches a block written in
        either family.
        """
        if self.address is None:
            return ()
        forms: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [self.address]
        if isinstance(self.address, ipaddress.IPv6Address):
            mapped = self.address.ipv4_mapped
            if mapped is not None:
                forms.append(mapped)
        else:
            forms.append(ipaddress.IPv6Address(f"::ffff:{self.address}"))
        return tuple(forms)

    @property
    def effective_port(self) -> int | None:
        """The port in use, falling back to the scheme's default port."""
        if self.port is not None:
            return self.port
        if self.scheme is not None:
            return DEFAULT_PORTS.get(self.scheme)
        return None

    def describe(self) -> str:
        """A short human-readable rendering of the normalised target."""
        if self.kind == "ip":
            base = str(self.address)
        elif self.kind in ("android-package", "ios-bundle", "repo"):
            return f"{self.kind} {self.identifier}"
        else:
            base = self.host or ""
        parts = []
        if self.scheme:
            parts.append(f"{self.scheme}://")
        parts.append(f"[{base}]" if ":" in base else base)
        if self.port is not None:
            parts.append(f":{self.port}")
        if self.path is not None:
            parts.append(path_segments_to_str(self.path))
        return "".join(parts)


def parse_target(raw: str, *, kind: str | None = None) -> Target:
    """Parse ``raw`` into a :class:`Target`.

    Detection, in order:

    * an explicit ``android:``, ``ios:`` or ``repo:`` prefix wins;
    * anything containing ``://`` is a URL;
    * anything that parses as an IP address, with or without a port or
      brackets, is an IP target;
    * anything else is a host, optionally with ``/path`` appended.

    Pass ``kind`` to force an interpretation, which is what you want for an
    Android package that is also a plausible hostname.
    """
    text = raw.strip()
    if not text:
        raise TargetError("empty target")

    if kind is not None:
        if kind not in TARGET_KINDS:
            raise TargetError(
                f"unknown target kind {kind!r}; expected one of {', '.join(TARGET_KINDS)}"
            )
        return _parse_as_kind(text, kind)

    lowered = text.lower()
    for prefix, forced in _EXPLICIT_PREFIXES.items():
        if lowered.startswith(prefix):
            return _parse_as_kind(text[len(prefix):].strip(), forced)

    if "://" in text:
        return _parse_url(text)
    if _looks_like_repo(text):
        return _parse_as_kind(text, "repo")
    return _parse_host_or_ip(text)


def _parse_as_kind(text: str, kind: str) -> Target:
    if kind == "repo":
        return Target(raw=text, kind="repo", identifier=_normalise_repo(text))
    if kind in ("android-package", "ios-bundle"):
        return Target(raw=text, kind=kind, identifier=_normalise_package(text, kind))
    if kind == "ip":
        return _parse_host_or_ip(text, require_ip=True)
    if kind == "host":
        return _parse_host_or_ip(text, require_host=True)
    raise TargetError(f"unknown target kind {kind!r}")


def _parse_url(text: str) -> Target:
    split = urlsplit(text)
    scheme = split.scheme.lower() or None
    if not split.netloc:
        raise TargetError(f"{text!r} looks like a URL but has no host")
    try:
        hostname = split.hostname
    except ValueError as exc:  # malformed IPv6 literal, bad port, ...
        raise TargetError(f"cannot parse host out of {text!r}: {exc}") from exc
    if not hostname:
        raise TargetError(f"{text!r} looks like a URL but has no host")
    try:
        port = split.port
    except ValueError as exc:
        raise TargetError(f"{text!r} has an invalid port: {exc}") from exc

    notes: list[str] = []
    if "%2f" in split.path.lower() or "%5c" in split.path.lower():
        notes.append(
            "path contains an encoded separator; it is compared as a literal "
            "character inside one segment, not as a segment boundary"
        )

    host = _normalise(hostname, "host")
    path = normalise_path(split.path)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    return Target(
        raw=text,
        kind="ip" if address is not None else "host",
        host=host,
        address=address,
        scheme=scheme,
        port=port,
        path=path,
        notes=tuple(notes),
    )


def _parse_host_or_ip(
    text: str, *, require_ip: bool = False, require_host: bool = False
) -> Target:
    """Parse ``host``, ``host/path``, ``host:port`` or an IP literal."""
    remainder = text
    path: tuple[str, ...] | None = None
    notes: list[str] = []

    # urlsplit carves the authority, path, query and fragment apart the same
    # way the scheme-ful branch does. Splitting on the first "/" by hand left
    # the query glued to the last path segment, so `example.com/api?x=1` and
    # `https://example.com/api?x=1` disagreed about the same target -- and the
    # entry side already refuses a query outright, so keeping one here was not
    # even self-consistent.
    carved = urlsplit("//" + remainder)
    remainder = carved.netloc
    if carved.path:
        raw_path = carved.path
        if "%2f" in raw_path.lower() or "%5c" in raw_path.lower():
            notes.append(
                "path contains an encoded separator; it is compared as a literal "
                "character inside one segment, not as a segment boundary"
            )
        path = normalise_path(raw_path)

    authority, port = _split_port(remainder)
    host = _normalise(authority, "host")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if require_ip and address is None:
        raise TargetError(f"{text!r} is not an IP address")
    if require_host and address is not None:
        raise TargetError(f"{text!r} is an IP address, not a hostname")

    return Target(
        raw=text,
        kind="ip" if address is not None else "host",
        host=host,
        address=address,
        port=port,
        path=path,
        notes=tuple(notes),
    )


def _split_port(authority: str) -> tuple[str, int | None]:
    """Split ``host:port``, leaving bare IPv6 literals intact."""
    text = authority.strip()
    if text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            raise TargetError(f"unterminated IPv6 literal in {authority!r}")
        host = text[: closing + 1]
        rest = text[closing + 1:]
        if rest.startswith(":"):
            return host, _parse_port(rest[1:], authority)
        if rest:
            raise TargetError(f"unexpected text after IPv6 literal in {authority!r}")
        return host, None
    if text.count(":") > 1:
        # A bare IPv6 literal without brackets; there is no port to split off.
        return text, None
    if ":" in text:
        host, _, port_text = text.partition(":")
        return host, _parse_port(port_text, authority)
    return text, None


def _parse_port(text: str, authority: str) -> int:
    if not text.isdigit():
        raise TargetError(f"invalid port in {authority!r}")
    port = int(text)
    if not 1 <= port <= 65535:
        raise TargetError(f"port out of range in {authority!r}")
    return port


def _normalise(host: str, context: str) -> str:
    from .errors import ScopeFileError

    try:
        return normalise_host(host, context=context)
    except ScopeFileError as exc:
        raise TargetError(str(exc)) from exc


def _normalise_package(text: str, kind: str) -> str:
    value = text.strip()
    if not value:
        raise TargetError(f"empty {kind}")
    if "/" in value or "*" in value:
        raise TargetError(f"{kind} {text!r} may not contain '/' or '*'")
    return value


def _looks_like_repo(text: str) -> bool:
    lowered = text.lower()
    return lowered.startswith("git@") or lowered.startswith("ssh://")


def _normalise_repo(text: str) -> str:
    """Reduce a repository reference to ``host/owner/name``.

    ``https://github.com/acme/widget.git``, ``git@github.com:acme/widget``
    and ``github.com/acme/widget`` all reduce to ``github.com/acme/widget``.
    The host is lowercased; the rest of the path keeps its case, because
    forge path components are case-sensitive on some hosts.
    """
    value = text.strip()
    if value.lower().startswith("git@"):
        value = value[4:]
        value = value.replace(":", "/", 1)
    elif "://" in value:
        split = urlsplit(value)
        host = split.netloc.rpartition("@")[2]
        value = f"{host}{split.path}"
    value = value.rstrip("/")
    if value.lower().endswith(".git"):
        value = value[:-4]
    host, _, rest = value.partition("/")
    if not host:
        raise TargetError(f"repo {text!r} has no host")
    return f"{host.lower()}/{rest}" if rest else host.lower()
