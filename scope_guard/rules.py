"""Scope entries, and the matching semantics that give them meaning.

A :class:`Rule` is one ``[[in_scope]]`` or ``[[out_of_scope]]`` entry with
every component normalised at construction time. Three relations are defined
over rules, and they are the whole substance of the tool:

:meth:`Rule.matches`
    does this entry cover this target?
:meth:`Rule.specificity`
    how precisely does it cover it, for precedence?
:func:`subsumes` / :func:`intersects`
    how do two entries relate to each other, which is what ``lint`` needs to
    reason about an author's intent.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import ScopeFileError
from .normalise import (
    host_labels,
    is_ip_literal,
    normalise_host,
    normalise_path,
    parse_ip,
    parse_network,
    path_segments_to_str,
)
from .targets import Target

__all__ = [
    "Rule",
    "RULE_TYPES",
    "SIDE_IN",
    "SIDE_OUT",
    "build_rule",
    "subsumes",
    "intersects",
    "wildcard_matches",
    "host_only_rule",
]

SIDE_IN = "in"
SIDE_OUT = "out"

#: Every entry ``type`` the scope-file format accepts.
RULE_TYPES = (
    "domain",
    "wildcard",
    "ip",
    "cidr",
    "url",
    "path",
    "android-package",
    "ios-bundle",
    "repo",
)

#: Which target kind each entry type can ever decide.
_FAMILY = {
    "domain": "host",
    "wildcard": "host",
    "ip": "ip",
    "cidr": "ip",
    "url": "net",          # host or ip, depending on how the URL is written
    "path": "net",
    "android-package": "android-package",
    "ios-bundle": "ios-bundle",
    "repo": "repo",
}

# Host-pattern discriminators, used by matching and by the lint algebra.
_H_EXACT = "exact-host"
_H_WILDCARD = "wildcard-host"
_H_IP = "exact-ip"
_H_NET = "network"
_H_ID_EXACT = "exact-id"
_H_ID_PREFIX = "id-prefix"


def wildcard_matches(base: str, host: str) -> bool:
    """True when ``host`` is a subdomain of ``base``.

    This is the single most important function in the tool, and the asymmetry
    it encodes is deliberate: ``*.example.com`` covers every subdomain but
    **not** the apex ``example.com``, which must be listed separately if it is
    in scope.

    Matching is done on whole labels, so a wildcard can never match across a
    label boundary:

    >>> wildcard_matches("example.com", "a.example.com")
    True
    >>> wildcard_matches("example.com", "a.b.example.com")
    True
    >>> wildcard_matches("example.com", "example.com")
    False
    >>> wildcard_matches("example.com", "notexample.com")
    False
    >>> wildcard_matches("example.com", "example.com.evil.net")
    False
    """
    suffix = "." + base
    return host.endswith(suffix) and len(host) > len(suffix)


@dataclass(frozen=True)
class Rule:
    """One normalised scope entry."""

    side: str
    type: str
    value: str
    index: int
    max_severity: str | None = None
    notes: str | None = None

    # Derived, normalised components.
    family: str = "host"
    host_kind: str = _H_EXACT
    host: str | None = None
    wildcard_base: str | None = None
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    scheme: str | None = None
    port: int | None = None
    path: tuple[str, ...] | None = None
    identifier: str | None = None
    id_prefix: tuple[str, ...] | None = None
    source: str = ""

    # ---------------------------------------------------------------- display

    @property
    def label(self) -> str:
        """How this entry is named in output: ``in_scope[2] wildcard *.x.com``."""
        side = "in_scope" if self.side == SIDE_IN else "out_of_scope"
        return f"{side}[{self.index}] {self.type} = {self.value!r}"

    # --------------------------------------------------------------- matching

    def matches(self, target: Target) -> bool:
        """True when this entry covers ``target``."""
        if not self._family_applies(target):
            return False
        if self.family in ("android-package", "ios-bundle", "repo"):
            return self._identifier_matches(target)
        if not self._host_matches(target):
            return False
        if not self._scheme_matches(target):
            return False
        if not self._port_matches(target):
            return False
        return self._path_matches(target)

    def _family_applies(self, target: Target) -> bool:
        if self.family == "net":
            return target.kind in ("host", "ip")
        if self.family == "host":
            return target.kind == "host"
        if self.family == "ip":
            return target.kind == "ip"
        return target.kind == self.family

    def _host_matches(self, target: Target) -> bool:
        if self.host_kind == _H_EXACT:
            return target.host == self.host
        if self.host_kind == _H_WILDCARD:
            # A wildcard is a DNS construct; it never covers a bare address.
            if target.kind != "host":
                return False
            return wildcard_matches(self.wildcard_base or "", target.host or "")
        if self.host_kind == _H_IP:
            return self.address in target.addresses
        if self.host_kind == _H_NET:
            network = self.network
            assert network is not None
            return any(
                address.version == network.version and address in network
                for address in target.addresses
            )
        return False

    def _scheme_matches(self, target: Target) -> bool:
        if self.scheme is None:
            return True
        if target.scheme is None:
            # The target was written without a scheme. Rather than silently
            # dropping scheme-constrained entries, treat the scheme as
            # unconstrained and surface it as a note on the decision.
            return True
        return target.scheme == self.scheme

    def _port_matches(self, target: Target) -> bool:
        if self.port is None:
            # An entry that does not write a port covers every port on that
            # host: a policy listing https://example.com means the site, not
            # only its :443 listener.
            return True
        target_port = target.effective_port
        if target_port is None:
            return True
        return target_port == self.port

    def _path_matches(self, target: Target) -> bool:
        if self.path is None:
            return True
        if target.path is None:
            # No path was supplied, so a path-scoped entry cannot decide it.
            return False
        return target.path[: len(self.path)] == self.path

    def _identifier_matches(self, target: Target) -> bool:
        identifier = target.identifier or ""
        if self.host_kind == _H_ID_PREFIX:
            prefix = self.id_prefix or ()
            parts = tuple(identifier.split("."))
            return len(parts) > len(prefix) and parts[: len(prefix)] == prefix
        if self.family == "repo":
            return identifier.lower() == (self.identifier or "").lower()
        return identifier == self.identifier

    # ------------------------------------------------------------ specificity

    def specificity(self) -> tuple[int, int, int]:
        """Rank how precisely this entry describes a target.

        The tuple is compared left to right: host precision first, then path
        depth, then how many of scheme and port are pinned. Host precision
        dominates deliberately -- a rule naming one host is a more direct
        statement about that host than a wildcard carrying a path.
        """
        return (self._host_score(), len(self.path or ()), self._constraint_score())

    def _host_score(self) -> int:
        if self.host_kind == _H_EXACT:
            return 3000 + 10 * len(host_labels(self.host or ""))
        if self.host_kind == _H_IP:
            # An entry naming one address is treated as more precise than any
            # CIDR covering it, including a /32 or /128.
            return 3000 + 10 * 8
        if self.host_kind == _H_NET:
            assert self.network is not None
            return 2000 + self.network.prefixlen
        if self.host_kind == _H_WILDCARD:
            return 1000 + 10 * len(host_labels(self.wildcard_base or ""))
        if self.host_kind == _H_ID_EXACT:
            return 3000 + 10 * len((self.identifier or "").split("."))
        if self.host_kind == _H_ID_PREFIX:
            return 1000 + 10 * len(self.id_prefix or ())
        return 0

    def _constraint_score(self) -> int:
        return (1 if self.scheme is not None else 0) + (1 if self.port is not None else 0)

    # ------------------------------------------------------------------ notes

    def constrains_path(self) -> bool:
        return self.path is not None

    @property
    def is_exact_host(self) -> bool:
        """True for an entry naming one hostname (``domain``, or a ``url``/
        ``path`` entry written against a concrete host)."""
        return self.host_kind == _H_EXACT

    @property
    def is_wildcard_host(self) -> bool:
        """True for an entry whose host part is a ``*.base`` wildcard."""
        return self.host_kind == _H_WILDCARD

    @property
    def resolution_group(self) -> str:
        """Which space of targets this entry can ever speak about.

        ``"hostname"`` and ``"address"`` are kept apart because scope-guard
        performs no DNS resolution: an entry about a netblock and an entry
        about a domain can never be shown to overlap, however related they
        are in reality.
        """
        if self.host_kind in (_H_IP, _H_NET):
            return "address"
        if self.host_kind in (_H_EXACT, _H_WILDCARD):
            return "hostname"
        return self.family

    def describe_normalised(self) -> str:
        """Render the entry as scope-guard understood it, not as it was typed."""
        if self.family in ("android-package", "ios-bundle", "repo"):
            if self.host_kind == _H_ID_PREFIX:
                return ".".join(self.id_prefix or ()) + ".*"
            return self.identifier or ""
        parts = []
        if self.scheme:
            parts.append(f"{self.scheme}://")
        if self.host_kind == _H_WILDCARD:
            parts.append(f"*.{self.wildcard_base}")
        elif self.host_kind == _H_NET:
            parts.append(str(self.network))
        elif self.host_kind == _H_IP:
            address = str(self.address)
            parts.append(f"[{address}]" if ":" in address else address)
        else:
            host = self.host or ""
            parts.append(f"[{host}]" if ":" in host else host)
        if self.port is not None:
            parts.append(f":{self.port}")
        if self.path is not None:
            parts.append(path_segments_to_str(self.path))
        return "".join(parts)


# --------------------------------------------------------------------- parsing


def build_rule(
    *,
    side: str,
    index: int,
    entry: dict[str, object],
    source: str = "",
) -> Rule:
    """Validate and normalise one scope-file entry into a :class:`Rule`."""
    where = f"{'in_scope' if side == SIDE_IN else 'out_of_scope'}[{index}]"

    unknown = set(entry) - {"type", "value", "max_severity", "notes"}
    if unknown:
        raise ScopeFileError(
            f"{where}: unknown key(s) {', '.join(sorted(unknown))}; "
            "expected type, value, max_severity, notes"
        )

    rule_type = entry.get("type")
    if not isinstance(rule_type, str):
        raise ScopeFileError(f"{where}: missing required string key 'type'")
    rule_type = rule_type.strip().lower()
    if rule_type not in RULE_TYPES:
        raise ScopeFileError(
            f"{where}: unknown type {rule_type!r}; expected one of "
            f"{', '.join(RULE_TYPES)}"
        )

    value = entry.get("value")
    if not isinstance(value, str) or not value.strip():
        raise ScopeFileError(f"{where}: missing required non-empty string key 'value'")
    value = value.strip()

    max_severity = entry.get("max_severity")
    if max_severity is not None and not isinstance(max_severity, str):
        raise ScopeFileError(f"{where}: 'max_severity' must be a string")
    notes = entry.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise ScopeFileError(f"{where}: 'notes' must be a string")

    common = {
        "side": side,
        "type": rule_type,
        "value": value,
        "index": index,
        "max_severity": max_severity,
        "notes": notes,
        "family": _FAMILY[rule_type],
        "source": source,
    }

    try:
        derived = _derive(rule_type, value, where)
    except ScopeFileError as exc:
        raise ScopeFileError(f"{where}: {exc}") from exc
    return Rule(**common, **derived)


def _derive(rule_type: str, value: str, where: str) -> dict[str, object]:
    if rule_type == "domain":
        host = normalise_host(value, context="domain value")
        if is_ip_literal(host):
            raise ScopeFileError(
                f"domain value {value!r} is an IP address; use type = \"ip\" instead"
            )
        return {"host_kind": _H_EXACT, "host": host}

    if rule_type == "wildcard":
        return {"host_kind": _H_WILDCARD, "wildcard_base": _wildcard_base(value)}

    if rule_type == "ip":
        return {"host_kind": _H_IP, "address": parse_ip(value, context="ip value")}

    if rule_type == "cidr":
        if "/" not in value:
            raise ScopeFileError(
                f"cidr value {value!r} has no prefix length; use type = \"ip\" for a "
                "single address"
            )
        return {"host_kind": _H_NET, "network": parse_network(value, context="cidr value")}

    if rule_type in ("url", "path"):
        return _derive_locator(rule_type, value)

    if rule_type in ("android-package", "ios-bundle"):
        return _derive_identifier(rule_type, value)

    if rule_type == "repo":
        from .targets import _normalise_repo  # local import: shared normalisation

        if value.endswith(".*"):
            prefix = tuple(value[:-2].split("."))
            raise ScopeFileError(
                f"repo value {value!r}: repo entries do not support '.*'; list each "
                f"repository, or use a {prefix[0]!r} entry of another type"
            )
        from .errors import TargetError

        try:
            identifier = _normalise_repo(value)
        except TargetError as exc:
            raise ScopeFileError(f"repo value {value!r}: {exc}") from exc
        if "/" not in identifier:
            raise ScopeFileError(
                f"repo value {value!r} names only a host; expected "
                "host/owner/name, e.g. github.com/acme/widget"
            )
        return {"host_kind": _H_ID_EXACT, "identifier": identifier}

    raise ScopeFileError(f"{where}: unhandled type {rule_type!r}")


def _wildcard_base(value: str) -> str:
    """Validate a wildcard entry and return its base domain.

    Only the leading-label form ``*.base`` is accepted. Partial-label
    wildcards such as ``api-*.example.com`` are rejected rather than
    half-supported, because an entry that silently matches less than its
    author intended is exactly the failure this tool exists to prevent.
    """
    if not value.startswith("*."):
        raise ScopeFileError(
            f"wildcard value {value!r} must start with '*.' (e.g. '*.example.com')"
        )
    base = value[2:]
    if "*" in base:
        raise ScopeFileError(
            f"wildcard value {value!r} may only contain one leading '*.' label; "
            "partial-label wildcards are not supported"
        )
    if not base:
        raise ScopeFileError("wildcard value '*.' has no base domain")
    normalised = normalise_host(base, context="wildcard base")
    if is_ip_literal(normalised):
        raise ScopeFileError(
            f"wildcard value {value!r} has an IP address as its base; use "
            "type = \"cidr\" for address ranges"
        )
    return normalised


def _derive_locator(rule_type: str, value: str) -> dict[str, object]:
    """Normalise a ``url`` or ``path`` entry."""
    text = value
    scheme: str | None = None
    if "://" in text:
        split = urlsplit(text)
        scheme = split.scheme.lower()
        authority = split.netloc.rpartition("@")[2]
        raw_path = split.path
        if split.query or split.fragment:
            raise ScopeFileError(
                f"{rule_type} value {value!r} has a query string or fragment; scope "
                "entries describe locations, not individual requests"
            )
    elif rule_type == "url":
        raise ScopeFileError(
            f"url value {value!r} has no scheme; write e.g. 'https://example.com/api' "
            "or use type = \"path\" to leave the scheme unconstrained"
        )
    else:
        authority, _, remainder = text.partition("/")
        raw_path = "/" + remainder if remainder else ""

    if not authority:
        raise ScopeFileError(f"{rule_type} value {value!r} has no host")

    host_text, port = _split_authority(authority, value, rule_type)
    path = normalise_path(raw_path)

    if rule_type == "path" and not path:
        raise ScopeFileError(
            f"path value {value!r} has no path component; use type = \"domain\" or "
            "type = \"wildcard\" to scope a whole host"
        )

    derived: dict[str, object] = {
        "scheme": scheme,
        "port": port,
        "path": path or None,
    }

    if host_text.startswith("*."):
        derived["host_kind"] = _H_WILDCARD
        derived["wildcard_base"] = _wildcard_base(host_text)
    else:
        host = normalise_host(host_text, context=f"{rule_type} host")
        if is_ip_literal(host):
            derived["host_kind"] = _H_IP
            derived["address"] = parse_ip(host, context=f"{rule_type} host")
            derived["host"] = host
        else:
            derived["host_kind"] = _H_EXACT
            derived["host"] = host
    return derived


def _split_authority(authority: str, value: str, rule_type: str) -> tuple[str, int | None]:
    text = authority.strip()
    if text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            raise ScopeFileError(
                f"{rule_type} value {value!r} has an unterminated IPv6 literal"
            )
        host = text[1:closing]
        rest = text[closing + 1:]
        if rest.startswith(":"):
            return host, _port(rest[1:], value, rule_type)
        if rest:
            raise ScopeFileError(
                f"{rule_type} value {value!r} has unexpected text after the IPv6 literal"
            )
        return host, None
    if text.count(":") > 1:
        return text, None
    if ":" in text:
        host, _, port_text = text.partition(":")
        return host, _port(port_text, value, rule_type)
    return text, None


def _port(text: str, value: str, rule_type: str) -> int:
    if not text.isdigit():
        raise ScopeFileError(f"{rule_type} value {value!r} has an invalid port")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ScopeFileError(f"{rule_type} value {value!r} has a port out of range")
    return port


def _derive_identifier(rule_type: str, value: str) -> dict[str, object]:
    if "/" in value:
        raise ScopeFileError(f"{rule_type} value {value!r} may not contain '/'")
    if value.endswith(".*"):
        prefix = tuple(part for part in value[:-2].split(".") if part)
        if not prefix:
            raise ScopeFileError(f"{rule_type} value {value!r} has no prefix before '.*'")
        return {"host_kind": _H_ID_PREFIX, "id_prefix": prefix}
    if "*" in value:
        raise ScopeFileError(
            f"{rule_type} value {value!r}: only a trailing '.*' wildcard is supported"
        )
    return {"host_kind": _H_ID_EXACT, "identifier": value}


# ---------------------------------------------------------------- rule algebra


def _host_subsumes(a: Rule, b: Rule) -> bool:
    """True when every host covered by ``b`` is also covered by ``a``."""
    if a.host_kind == _H_EXACT:
        return b.host_kind == _H_EXACT and a.host == b.host
    if a.host_kind == _H_WILDCARD:
        base = a.wildcard_base or ""
        if b.host_kind == _H_EXACT:
            return wildcard_matches(base, b.host or "")
        if b.host_kind == _H_WILDCARD:
            other = b.wildcard_base or ""
            return other == base or wildcard_matches(base, other)
        return False
    if a.host_kind == _H_IP:
        if b.host_kind == _H_IP:
            return _same_address(a.address, b.address)
        return False
    if a.host_kind == _H_NET:
        network = a.network
        assert network is not None
        if b.host_kind == _H_IP:
            return _address_in(b.address, network)
        if b.host_kind == _H_NET:
            other = b.network
            assert other is not None
            if other.version != network.version:
                return False
            return other.subnet_of(network)
        return False
    if a.host_kind == _H_ID_EXACT:
        return b.host_kind == _H_ID_EXACT and _same_identifier(a, b)
    if a.host_kind == _H_ID_PREFIX:
        prefix = a.id_prefix or ()
        if b.host_kind == _H_ID_EXACT:
            parts = tuple((b.identifier or "").split("."))
            return len(parts) > len(prefix) and parts[: len(prefix)] == prefix
        if b.host_kind == _H_ID_PREFIX:
            other = b.id_prefix or ()
            return len(other) >= len(prefix) and other[: len(prefix)] == prefix
        return False
    return False


def _host_intersects(a: Rule, b: Rule) -> bool:
    """True when some host could be covered by both ``a`` and ``b``."""
    return _host_subsumes(a, b) or _host_subsumes(b, a)


def _same_address(left, right) -> bool:
    if left is None or right is None:
        return False
    return _canonical_v6(left) == _canonical_v6(right)


def _canonical_v6(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _address_in(address, network) -> bool:
    if address is None:
        return False
    candidates = [address]
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        candidates.append(address.ipv4_mapped)
    elif isinstance(address, ipaddress.IPv4Address):
        candidates.append(ipaddress.IPv6Address(f"::ffff:{address}"))
    return any(c.version == network.version and c in network for c in candidates)


def _same_identifier(a: Rule, b: Rule) -> bool:
    if a.family == "repo":
        return (a.identifier or "").lower() == (b.identifier or "").lower()
    return a.identifier == b.identifier


def _families_comparable(a: Rule, b: Rule) -> bool:
    groups = {
        "host": "web",
        "ip": "web",
        "net": "web",
    }
    left = groups.get(a.family, a.family)
    right = groups.get(b.family, b.family)
    return left == right


def _path_prefix_of(shorter: tuple[str, ...], longer: tuple[str, ...]) -> bool:
    return longer[: len(shorter)] == shorter


def subsumes(a: Rule, b: Rule) -> bool:
    """True when every target matched by ``b`` is also matched by ``a``.

    Deliberately conservative: it answers ``True`` only when the containment
    is provable from the entries alone. Anything needing a DNS lookup to
    decide is ``False``, because scope-guard does not perform lookups.
    """
    if not _families_comparable(a, b):
        return False
    if not _host_subsumes(a, b):
        return False
    if a.scheme is not None and a.scheme != b.scheme:
        return False
    if a.port is not None and a.port != b.port:
        return False
    if a.path is not None:
        if b.path is None:
            return False
        if not _path_prefix_of(a.path, b.path):
            return False
    return True


def intersects(a: Rule, b: Rule) -> bool:
    """True when some single target could be matched by both entries."""
    if not _families_comparable(a, b):
        return False
    if not _host_intersects(a, b):
        return False
    if a.scheme is not None and b.scheme is not None and a.scheme != b.scheme:
        return False
    if a.port is not None and b.port is not None and a.port != b.port:
        return False
    if a.path is not None and b.path is not None:
        if not (_path_prefix_of(a.path, b.path) or _path_prefix_of(b.path, a.path)):
            return False
    return True


def host_only_rule(target: Target) -> Rule:
    """A throwaway entry covering exactly ``target``'s host, nothing else.

    Used to ask the algebra questions about a target rather than about
    another entry -- "do any path-scoped entries apply to this host?" -- so
    that :func:`intersects` stays a relation between rules.
    """
    is_ip = target.kind == "ip"
    return Rule(
        side=SIDE_IN,
        type="ip" if is_ip else "domain",
        value=target.raw,
        index=-1,
        family="ip" if is_ip else "host",
        host_kind=_H_IP if is_ip else _H_EXACT,
        host=target.host,
        address=target.address,
    )
