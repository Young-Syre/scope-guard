# scope-guard

[![tests](https://github.com/Young-Syre/scope-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/scope-guard/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)

**Was that host in scope? Answer it mechanically, before you touch it.**

You test a host, you write the report, and it comes back closed: the asset was
never in scope. That is the cheap version. The expensive version is that you
tested something you had no authorisation to touch at all.

Scope is not a list of domains. It is wildcards, netblocks, path prefixes,
explicit carve-outs and precedence rules, and almost everyone resolves it by
eye, at the moment they are most eager to start. `scope-guard` makes that
decision mechanical: given a declarative scope file and a target, it returns
**in-scope**, **out-of-scope** or **unknown**, and names the exact entry that
decided it.

> ### This tool is an offline authorisation check. It makes no network requests and touches no target.
>
> No DNS resolution, no policy page fetch, no probe, no telemetry. The core
> decision path is the Python standard library and nothing else, so there is
> no dependency in the tree that could reach the network on your behalf. Every
> verdict comes from the scope file you wrote — which is what makes a verdict
> something you can show to someone afterwards.

---

## Install

```sh
git clone https://github.com/Young-Syre/scope-guard
cd scope-guard
pip install .
```

Python 3.11 or newer. No runtime dependencies.

## Use

```sh
scope-guard init my-programme.toml       # scaffold a commented scope file
# ...transcribe the programme's asset table into it by hand...
scope-guard lint my-programme.toml       # catch your authoring mistakes

scope-guard check https://api.example.com/v2 --scope my-programme.toml
```

```
$ scope-guard check https://api.meridianpay.example/v2/users --scope examples/primacy-of-rules.toml
IN-SCOPE  https://api.meridianpay.example/v2/users
  reason: included by in_scope[1] wildcard = '*.meridianpay.example'
  rule:   in_scope[1] wildcard = '*.meridianpay.example'
          normalised as *.meridianpay.example
          note: All production subdomains.
```

`--explain` shows the whole decision, including the entries that matched but
lost:

```
$ scope-guard check "https://meridianpay.example/api/../legal/terms" \
      --scope examples/primacy-of-rules.toml --explain
OUT-OF-SCOPE  https://meridianpay.example/api/../legal/terms
  reason: excluded by out_of_scope[3] path = 'meridianpay.example/legal'
  rule:   out_of_scope[3] path = 'meridianpay.example/legal'
          normalised as meridianpay.example/legal
          note: Served from an external CMS. A prefix match on whole segments, so it covers /legal/terms but not /legalese.
  decision tree:
    target: https://meridianpay.example/api/../legal/terms
    normalised: https://meridianpay.example/legal/terms  (kind: host)
    settings: exclusions_win=true, unlisted_is=out
    matched 2 entries:
      - out_of_scope[3] path = 'meridianpay.example/legal' -> meridianpay.example/legal [specificity (3020, 1, 0)]
      - in_scope[0] domain = 'meridianpay.example' -> meridianpay.example [specificity (3020, 0, 0)]
    exclusions_win is true and at least one out_of_scope entry matched, so the exclusion decides regardless of specificity
    entries that matched but did not decide:
      - in_scope[0] domain = 'meridianpay.example'
```

`--scope` may be omitted if you set `$SCOPE_GUARD_SCOPE` or keep a
`scope.toml` in the working directory.

## Exit codes

The exit code is the interface. Scripts should rely on it rather than on the
text.

| Code | Meaning |
|---|---|
| `0` | **in-scope** — an entry authorises this target |
| `1` | **out-of-scope** — an entry excludes it, or nothing listed it and the programme works on primacy of rules |
| `2` | **unknown** — nothing decided it, or two entries of equal weight disagreed. **This is not permission.** It is the prompt to go and ask |
| `3` | usage error, unreadable scope file, or unparseable target. Deliberately distinct from the three verdicts, so a broken invocation can never be mistaken for a green light |

## Scope file format

TOML. Three parts: who the programme is, how the entries combine, and the
entries themselves.

### `[program]`

Metadata, and the audit trail for where these entries came from.

| Key | Type | Notes |
|---|---|---|
| `name` | string | The programme's name, so one scope file is not mistaken for another. |
| `platform` | string | Free-form: `hackerone`, `bugcrowd`, `intigriti`, `self-hosted`, … |
| `policy_url` | string | Where you read these entries. Without it nobody can re-verify the file. `lint` warns. |
| `last_verified` | date | The day you last read that policy page **yourself**. A TOML date (`2026-10-29`) or an ISO-8601 string. `lint` warns once it is stale. |
| `notes` | string | Anything you want to remember about how you read the policy. |

`policy-url` and `last-verified` are accepted as aliases.

### `[rules]`

| Key | Default | Meaning |
|---|---|---|
| `exclusions_win` | `true` | When true, a matching `out_of_scope` entry decides the verdict however general it is. **This is the correct default.** An exclusion is a prohibition, and a prohibition that a more specific permission can outvote is not a prohibition. Set it to `false` only if you have read [Precedence](#precedence) and genuinely want most-specific-wins. |
| `unlisted_is` | `"out"` | What a target matching nothing means. `"out"` models a **primacy-of-rules** programme: not listed, not authorised. `"unknown"` models a **primacy-of-impact** programme, where anything the organisation owns may count, so an unlisted asset is a question rather than a yes or a no. |

### `[[in_scope]]` and `[[out_of_scope]]`

Arrays of entries. Each entry takes:

| Key | Required | Meaning |
|---|---|---|
| `type` | yes | One of the entry types below. |
| `value` | yes | The value, in the form that type expects. |
| `max_severity` | no | A severity ceiling the programme stated for this asset. Reported on an in-scope verdict; the tightest ceiling among the deciding entries wins. Conventionally `critical`, `high`, `medium`, `low`, `info` or `none`, but any string is accepted. |
| `notes` | no | Why this entry exists. Printed with the verdict it decides, which is where you will want it. |

### Entry types

| `type` | `value` shape | Matches |
|---|---|---|
| `domain` | `example.com` | That exact host, and only it. Not subdomains. |
| `wildcard` | `*.example.com` | Every subdomain of `example.com`, at any depth. **Not the apex** — see below. |
| `ip` | `192.0.2.5`, `2001:db8::1` | That exact address. IPv4 and IPv6. |
| `cidr` | `192.0.2.0/24`, `2001:db8::/32` | Any address in the block. Host bits are allowed and masked off (`192.0.2.5/24` means `192.0.2.0/24`). |
| `url` | `https://example.com:8443/api` | Scheme is required and pinned. Port pinned if written. Path is a **prefix** match (see below). |
| `path` | `example.com/api`, `*.example.com/api` | Same as `url` but with the scheme left unconstrained. The host part may be a wildcard. Must have a path. |
| `android-package` | `com.example.app`, `com.example.*` | An Android package, or with a trailing `.*`, every package under that prefix. |
| `ios-bundle` | `com.example.app`, `com.example.*` | The same for an iOS bundle identifier. |
| `repo` | `github.com/acme/widget` | One repository. `https://…`, `git@host:owner/name` and a trailing `.git` all normalise to the same thing. |

An entry whose form is wrong is a **hard error**, not a warning. `type = "domain"`
with `*.example.com` as its value, a wildcard like `api-*.example.com`, a
`cidr` with no prefix length, a `url` with no scheme — `scope-guard` refuses to
load the file rather than guessing. A scope file that is quietly misread is
worse than no scope file at all.

## Matching semantics

This section is the tool. Everything else is plumbing.

### The wildcard/apex asymmetry

**`*.example.com` does not match `example.com`.** If the apex is in scope, it
needs its own `domain` entry. This single asymmetry is where people make
mistakes in both directions: testing an apex a wildcard never covered, and
dismissing an apex a programme did list.

With `*.example.com` alone:

| Target | | Why |
|---|---|---|
| `a.example.com` | ✅ matches | a subdomain |
| `a.b.c.example.com` | ✅ matches | wildcards cover any depth |
| `A.EXAMPLE.COM` | ✅ matches | hosts are case-insensitive |
| `a.example.com.` | ✅ matches | the trailing dot is the same host |
| `shop.xn--bcher-kva.example` | ✅ matches `*.bücher.example` | IDN is normalised to ASCII before comparing |
| `example.com` | ❌ no match | **the apex is not a subdomain of itself** |
| `notexample.com` | ❌ no match | matching is on whole labels, not string suffixes |
| `evil-example.com` | ❌ no match | same reason |
| `example.com.evil.net` | ❌ no match | the base must be a *suffix*, not a substring |
| `192.0.2.5` | ❌ no match | a wildcard is a DNS construct and never covers a bare address |

Only the leading-label form `*.base` is supported. `api-*.example.com` is
rejected outright rather than half-implemented, because an entry that silently
matches less than its author intended is exactly the failure this tool exists
to prevent.

### Paths are prefix matches on whole segments

A `path` or `url` entry matches when its segments are a prefix of the target's
segments. Partial segments never match.

With `path = "example.com/api"`:

| Target | | Why |
|---|---|---|
| `https://example.com/api` | ✅ | the prefix itself |
| `https://example.com/api/v1/users` | ✅ | `/api` is a segment prefix |
| `https://example.com/apifoo` | ❌ | `apifoo` is a different segment, not `api` plus more |
| `https://example.com/API` | ❌ | paths are case-sensitive; hosts are not |
| `https://example.com/api/../admin` | ❌ | resolves to `/admin`, so the `/api` entry does not apply |
| `https://example.com/api/%2e%2e/admin` | ❌ | the same, after decoding |
| `https://example.com/api%2Fv1` | ❌ | `%2F` is a literal character inside one segment, not a separator |
| `example.com` (no path) | ❌ | a path entry cannot decide a target that has no path |

Normalisation happens in a deliberate order: **split on `/` first**, so an
encoded separator cannot invent a segment boundary; then percent-decode each
segment; then resolve `.` and `..`. Resolving dot segments *after* decoding is
stricter than RFC 3986, which would treat `%2e%2e` as an ordinary segment. The
strict reading is the correct one for an authorisation check: if a request
could reach `/admin` on some server, the verdict should be the verdict for
`/admin`. Traversal past the root is clamped, as servers clamp it.

### Hosts are normalised before comparison

`EXAMPLE.com`, `example.com.` and `example.com` are one host. Unicode is
IDNA-encoded, so `bücher.example` and `xn--bcher-kva.example` are one host, in
entries and in targets alike. IP literals are canonicalised, so `2001:DB8::0:1`
and `2001:db8::1` are one address, with or without brackets.

### Addresses, and the IPv4-mapped case

CIDR membership is computed with `ipaddress`, for both families. An
IPv4-mapped IPv6 target matches an IPv4 block and vice versa, in either
spelling:

```sh
scope-guard check ::ffff:203.0.113.42 --scope examples/primacy-of-rules.toml   # in-scope, via 203.0.113.0/24
scope-guard check ::ffff:cb00:712a    --scope examples/primacy-of-rules.toml   # the same address, the same verdict
```

A **hostname is never resolved to an address.** A `cidr` entry cannot decide a
hostname target, and `scope-guard` says so in the verdict rather than letting
you assume it was considered:

```
$ scope-guard check some.host.example --scope examples/primacy-of-impact.toml
UNKNOWN  some.host.example
  reason: no entry matched, and unlisted_is = "unknown" (primacy of impact): ask the programme before testing
  note:   4 address-based entries (ip/cidr) were not evaluated: the target is a hostname, and scope-guard performs no DNS resolution. Resolve it yourself and re-check the address if an address range matters here.
```

Resolve the name yourself and check the address as a second question. That is a
deliberate trade: a tool that resolved names would be a tool that makes network
requests.

### Schemes and ports

* A scheme pinned in an entry is enforced: `https://example.com/api` does not
  match `http://example.com/api`.
* A port is enforced **only when written**. `https://example.com` matches
  `https://example.com:8443/x` — a policy listing a site means the site, not
  only its `:443` listener. Write `https://example.com:8443` to pin a port.
* `https://example.com:443` and `https://example.com` are the same, via the
  scheme's default port.
* A target given **without** a scheme (`example.com/api`) is matched as though
  any scheme were acceptable, and the verdict says so in a note. People type
  bare hosts; dropping scheme-pinned entries silently would be worse.

Pinning only restricts something if no broader entry also covers the host.
`https://app.example.com` in scope next to `*.example.com` restricts nothing,
because the wildcard covers that host on every scheme. `lint` warns about this
(SG001/SG003) because it is a quiet way to believe your authorisation is
narrower than what you actually wrote. To mean "https only", exclude the other
scheme.

### Precedence

Applied in this order:

1. **Nothing matched.** The verdict comes from `unlisted_is`: `out` for
   primacy of rules, `unknown` for primacy of impact.
2. **An exclusion matched and `exclusions_win` is true** (the default). Out of
   scope, and the most specific matching exclusion is named. Specificity does
   not rescue an inclusion here, by design.
3. **Otherwise the most specific match wins.** Specificity is compared as a
   tuple: host precision first, then path depth, then how many of scheme and
   port are pinned. Host precision dominates deliberately — an entry naming one
   host is a more direct statement about that host than a wildcard carrying a
   path.
   * exact host > CIDR > wildcard; a deeper wildcard beats a shallower one; a
     tighter CIDR beats a looser one; an exact `ip` entry beats any CIDR
     containing it, including a `/32`.
4. **Equal specificity, opposite verdicts** (only reachable with
   `exclusions_win = false`). `unknown`, with both entries named. The tool does
   not guess — that is the question to put to the programme.

## Filtering a recon list before you touch anything

`batch` reads targets one per line from a file or stdin, skipping blanks and
`#` comments. This is the point of the tool: the scope check happens *before*
the scanner, not after the report is rejected.

```sh
subfinder -d example.com -silent \
  | scope-guard batch - --scope my-programme.toml --format plain --only in \
  | httpx -silent \
  | nuclei -t ~/nuclei-templates/
```

Nothing out of scope reaches `httpx`, so nothing out of scope reaches the
scanner. For the record you keep, take the CSV instead:

```
$ scope-guard batch recon.txt --scope examples/primacy-of-rules.toml
target,verdict,exit_code,deciding_rule,rule_type,rule_value,max_severity,reason
meridianpay.example,in-scope,0,in_scope[0] domain = 'meridianpay.example',domain,meridianpay.example,,included by in_scope[0] domain = 'meridianpay.example'
api.meridianpay.example,in-scope,0,in_scope[1] wildcard = '*.meridianpay.example',wildcard,*.meridianpay.example,,included by in_scope[1] wildcard = '*.meridianpay.example'
a.sandbox.meridianpay.example,out-of-scope,1,out_of_scope[0] wildcard = '*.sandbox.meridianpay.example',wildcard,*.sandbox.meridianpay.example,,excluded by out_of_scope[0] wildcard = '*.sandbox.meridianpay.example'
blog.other.invalid,out-of-scope,1,,,,,"no entry matched, and unlisted_is = ""out"" (primacy of rules): anything not listed is out of scope"
203.0.113.42,in-scope,0,in_scope[4] cidr = '203.0.113.0/24',cidr,203.0.113.0/24,,included by in_scope[4] cidr = '203.0.113.0/24'
203.0.113.1,out-of-scope,1,out_of_scope[4] ip = '203.0.113.1',ip,203.0.113.1,,excluded by out_of_scope[4] ip = '203.0.113.1'
```

Other flags: `--format json` for the full decision per target including the
trace, `-o FILE` to write to a file, and `--strict` to exit `1` if **any**
target was not in scope, which makes `batch` usable as a CI gate. An
unparseable target becomes an `error` row rather than killing the run.

## `lint` — checks on the scope file itself

The other half of the tool looks at your authorisation record rather than at a
target. A scope file can be valid TOML and still not say what you thought it
said.

```sh
scope-guard lint my-programme.toml            # exit 1 on any error
scope-guard lint my-programme.toml --strict   # exit 1 on warnings too
scope-guard lint my-programme.toml --json
```

| Check | Severity | What it catches |
|---|---|---|
| **SG001** | warning / info | An entry fully covered by another on the same side (a CIDR containing a listed IP, a host entry containing a path entry). Info when the redundant entry still carries its own `max_severity` or `notes`. Also warns when the narrower entry pins a scheme or port that the broader entry undercuts, so the pin restricts nothing. |
| **SG002** | warning / info | An `out_of_scope` entry no `in_scope` entry can ever reach, so it enforces nothing. Deliberately silent under `unlisted_is = "unknown"`, where a non-overlapping exclusion is the only way to turn an `unknown` into a firm `out-of-scope`. Info when nothing in scope is even of a comparable kind. |
| **SG003** | warning / info | A wildcard that subsumes a sibling entry on the same side. Same severity logic as SG001. |
| **SG004** | warning | A wildcard whose apex is not addressed. `*.example.com` plus no `example.com` entry means a check of the apex falls through to `unlisted_is`. An apex listed on the *other* side counts as deliberate; a covering wildcard only counts on the same side. |
| **SG005** | info / warning | An in-scope CIDR containing a host listed out of scope. Info when the carve-out holds; **warning** when `exclusions_win = false` and the inclusion is at least as specific, because then the carve-out loses and those addresses come back in scope. |
| **SG006** | warning / error | `last_verified` missing, or older than `--max-age-days` (default 90). Error if it is in the future. Scope drifts without telling you; a stale scope file is a liability. |
| **SG007** | warning | The same entry listed twice on the same side, after normalisation. |
| **SG008** | error | The same entry listed both in scope and out of scope. The exclusion wins and the inclusion is dead; one of them is not what you meant. |
| **SG009** | warning / info | `[program]` metadata missing. Warning for `policy_url`, without which nobody can re-verify the file; info for `name` and `platform`. |
| **SG010** | error / warning | An `in_scope` entry entirely inside an `out_of_scope` entry. With `exclusions_win = true` it can never return in-scope, so it is dead code in your authorisation record. |

`examples/broken-scope.toml` is deliberately wrong and fires all ten, so you
can see each finding before you meet it in a real file:

```sh
scope-guard lint examples/broken-scope.toml
```

## Examples

* [`examples/primacy-of-rules.toml`](examples/primacy-of-rules.toml) — a
  programme with an explicit asset table. `unlisted_is = "out"`.
* [`examples/primacy-of-impact.toml`](examples/primacy-of-impact.toml) — a
  programme that cares about impact on the organisation.
  `unlisted_is = "unknown"`, which makes exclusions the only way to say a firm
  no.
* [`examples/broken-scope.toml`](examples/broken-scope.toml) — every lint
  check, firing.

Both realistic files are fictional, and every name in them uses the `.example`
TLD reserved by RFC 6761 with documentation addresses from RFC 5737 and RFC
3849, so nothing in them can resolve to a real host. That is deliberate: an
example scope file containing a live domain is a loaded gun. They are built
from the *shape* of public policies, not from any real programme's text, and
no programme is named.

Their `last_verified` dates will eventually go stale and SG006 will start
warning on them. That is the check doing its job, demonstrated on the way past.

## Why not just read the policy page?

You should read the policy page. This tool cannot read it for you and does not
try.

What it does is make your reading of it re-checkable. Reading a policy is a
one-time act of attention at the start, and the decisions it governs come later
— a hundred hosts into a subdomain sweep, at the end of a long session, when
you have found something and want it to be in scope. That is the point at which
an eyeballed wildcard becomes a wrong assumption, and the asymmetry between
`*.example.com` and `example.com` becomes a closed report. Transcribing the
policy once and then asking a program is not a substitute for reading; it is
how the reading survives contact with a recon list.

The honest version of the pitch is narrow. The value is in three things:
transcription forces you to decide what each line of the policy actually means
while you are still paying attention; the matching rules are then applied the
same way every time, including the cases below that are easy to get wrong by
hand; and a verdict names the entry that produced it, which is an artefact you
can show someone. If you only ever test one host from one policy you read five
minutes ago, you do not need this.

## Limitations

Stated plainly, because a tool like this is only worth having if you know what
it does not do.

* **It only knows what you tell it.** Every verdict is a statement about your
  scope file, not about reality. A wrong entry produces a confident wrong
  answer.
* **It cannot read a programme's policy page.** There is no fetching, no
  parsing of policy prose, and no platform API. Transcription is manual and
  that is the design: a human decided what each entry means, and the file
  records that decision.
* **A human has to keep it current.** Scope changes without notice. That is why
  `last_verified` exists, why `lint` warns when it goes stale, and why the
  warning is not something to silence.
* **No DNS resolution**, so address entries never decide hostname targets, and
  hostname entries never decide address targets. The verdict tells you when
  entries were skipped for this reason.
* **`unknown` is not permission.** Exit code `2` means go and ask.
* **An in-scope verdict is not consent for any particular test.** It says the
  asset is listed. Rate limits, prohibited techniques, account-creation rules
  and testing windows live in the policy prose, and `scope-guard` has no
  opinion on them.
* **A verdict on a bare host is a verdict on the host**, not on every path
  under it. The output says so when path-scoped entries exist that it could not
  evaluate.
* **Specificity ties are not resolved by guessing.** With
  `exclusions_win = false` you can construct genuine ambiguity, and the tool
  returns `unknown` with both entries named rather than inventing an answer.

## Tests

```sh
python -m unittest discover -s tests -t . -v
```

268 tests, standard library `unittest`, no network access. They cover every
matching rule above including the adversarial cases (`example.com.evil.net`,
`notexample.com`, `/apifoo`, `/api/../admin`, `/api/%2e%2e/admin`, `%2F`,
IPv4-mapped IPv6, trailing dots, uppercase, punycode), precedence and
exclusion-wins under both settings, all three verdict exit codes, `unlisted_is`
for both programme shapes, and every lint check firing on the broken example
while staying silent on the clean ones.

## Licence

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 David Nichols.
