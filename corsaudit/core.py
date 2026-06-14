"""Core CORS misconfiguration detection engine.

The engine inspects a set of HTTP response headers (typically the response to a
cross-origin / preflight probe you already captured) plus the Origin that was
sent in the request, and reports CORS weaknesses.

Detections (each maps to a stable rule id):
  CORS001  wildcard '*' origin reflected together with credentials=true
           (illegal per spec; if a browser honored it, the worst case)
  CORS002  Access-Control-Allow-Origin reflects the request Origin AND
           credentials=true  (origin reflection + creds -> account takeover risk)
  CORS003  Access-Control-Allow-Origin == '*' (permissive, no credentials)
  CORS004  'null' origin allowed (sandboxed iframe / data: URI bypass)
  CORS005  Origin reflected without credentials (info / weak)
  CORS006  Trusts arbitrary subdomain / prefix-suffix style match
           (e.g. allows evil-trusted.com or trusted.com.attacker.com)
  CORS007  Insecure scheme: https resource trusts an http:// origin
  CORS008  Access-Control-Allow-Methods includes broad/dangerous verbs
           together with credentials (PUT/DELETE/PATCH)
  CORS009  Multiple Access-Control-Allow-Origin values returned (invalid;
           often a sign of a buggy reflector)

No network access is performed anywhere in this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# Higher number == more severe. Used for sorting + exit-code decisions.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    origin: Optional[str] = None
    evidence: Dict[str, str] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _norm_headers(headers: Dict[str, object]) -> Dict[str, List[str]]:
    """Lower-case header names; coerce each value to a list of strings.

    Accepts values that are str or list/tuple of str (some HTTP libraries
    return multiple values for a repeated header).
    """
    out: Dict[str, List[str]] = {}
    for k, v in headers.items():
        key = str(k).strip().lower()
        if isinstance(v, (list, tuple)):
            vals = [str(x).strip() for x in v]
        else:
            vals = [str(v).strip()]
        out.setdefault(key, []).extend(vals)
    return out


def parse_header_block(text: str) -> Dict[str, List[str]]:
    """Parse a raw 'Name: value' header block (one per line) into a dict.

    Repeated header names are preserved as multiple list entries. Lines without
    a colon (e.g. an HTTP status line) are ignored.
    """
    headers: Dict[str, List[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if not name:
            continue
        headers.setdefault(name, []).append(value.strip())
    return headers


def _is_true(value: str) -> bool:
    return value.strip().lower() == "true"


def _scheme_host(origin: str) -> Tuple[str, str]:
    """Return (scheme, host[:port]) for an origin string; best-effort."""
    o = origin.strip()
    scheme = ""
    rest = o
    if "://" in o:
        scheme, _, rest = o.partition("://")
    rest = rest.split("/", 1)[0]
    return scheme.lower(), rest.lower()


def _looks_like_loose_match(request_origin: str, allowed: str) -> Optional[str]:
    """Heuristic for prefix/suffix/substring trust bypasses.

    Returns a human reason if the allowed value appears to trust the request
    origin via a sloppy substring/endswith/startswith check rather than an
    exact, parsed match. Returns None otherwise.
    """
    if not request_origin or not allowed:
        return None
    _, req_host = _scheme_host(request_origin)
    _, allow_host = _scheme_host(allowed)
    if not req_host or not allow_host:
        return None
    if req_host == allow_host:
        return None  # exact host match is fine
    # The server echoed our (attacker-controlled) origin even though it is not
    # an exact match of a configured host: classic reflection bypass shapes.
    if req_host.endswith("." + allow_host) is False and allow_host in req_host:
        return (
            "allowed host '%s' appears as a substring of the trusted origin '%s'"
            % (allow_host, req_host)
        )
    return None


def analyze_headers(
    headers: Dict[str, object],
    request_origin: Optional[str] = None,
) -> List[Finding]:
    """Analyze a single response's headers for CORS misconfiguration.

    headers: mapping of response header name -> value (str or list of str).
    request_origin: the Origin header that was sent in the probe request, if
        known. Required to detect reflection-based issues precisely.

    Raises TypeError if *headers* is not a dict-like mapping.
    """
    if headers is None:
        raise TypeError("headers must be a dict, got None")
    if not isinstance(headers, dict):
        raise TypeError(
            "headers must be a dict, got {}".format(type(headers).__name__)
        )
    h = _norm_headers(headers)
    findings: List[Finding] = []

    acao_vals = h.get("access-control-allow-origin", [])
    acac_vals = h.get("access-control-allow-credentials", [])
    methods_vals = h.get("access-control-allow-methods", [])

    credentials = any(_is_true(v) for v in acac_vals)
    acao = acao_vals[0] if acao_vals else None

    # CORS009: multiple distinct ACAO values (invalid + usually a buggy reflector)
    if len({v for v in acao_vals}) > 1:
        findings.append(
            Finding(
                rule="CORS009",
                severity="medium",
                title="Multiple Access-Control-Allow-Origin values",
                detail=(
                    "The response returned more than one distinct "
                    "Access-Control-Allow-Origin value, which is invalid per "
                    "the Fetch spec and often indicates a custom origin "
                    "reflector layered on top of a framework default."
                ),
                origin=request_origin,
                evidence={"access-control-allow-origin": ", ".join(acao_vals)},
                remediation="Emit exactly one ACAO value computed from an allowlist.",
            )
        )

    if acao is not None:
        acao_l = acao.strip().lower()

        if acao.strip() == "*":
            if credentials:
                # Spec forbids '*' + credentials, but flag it as the worst case:
                findings.append(
                    Finding(
                        rule="CORS001",
                        severity="critical",
                        title="Wildcard origin combined with credentials",
                        detail=(
                            "Access-Control-Allow-Origin is '*' while "
                            "Access-Control-Allow-Credentials is true. This "
                            "combination is rejected by browsers, but its "
                            "presence means the server is configured to share "
                            "credentialed responses with any origin -- a "
                            "critical misconfiguration if any layer honors it."
                        ),
                        origin=request_origin,
                        evidence={
                            "access-control-allow-origin": acao,
                            "access-control-allow-credentials": "true",
                        },
                        remediation=(
                            "Never combine wildcard origin with credentials. "
                            "Reflect only allowlisted origins and set "
                            "credentials=true only for those."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule="CORS003",
                        severity="low",
                        title="Wildcard origin (no credentials)",
                        detail=(
                            "Access-Control-Allow-Origin is '*'. Acceptable for "
                            "truly public, non-credentialed resources, but "
                            "review whether the data is meant to be public."
                        ),
                        origin=request_origin,
                        evidence={"access-control-allow-origin": "*"},
                        remediation=(
                            "Confirm the endpoint serves only public data; "
                            "otherwise restrict to an allowlist."
                        ),
                    )
                )

        elif acao_l == "null":
            findings.append(
                Finding(
                    rule="CORS004",
                    severity="high" if credentials else "medium",
                    title="'null' origin allowed",
                    detail=(
                        "The server trusts the 'null' origin. An attacker can "
                        "forge a 'null' Origin from a sandboxed iframe or a "
                        "data:/file: document, bypassing the allowlist"
                        + (" -- and credentials are shared." if credentials else ".")
                    ),
                    origin=request_origin,
                    evidence={
                        "access-control-allow-origin": "null",
                        "access-control-allow-credentials": str(credentials).lower(),
                    },
                    remediation="Never allowlist the 'null' origin.",
                )
            )

        elif request_origin and acao.strip().lower() == request_origin.strip().lower():
            # The server reflected exactly the origin we sent -> reflection.
            if credentials:
                findings.append(
                    Finding(
                        rule="CORS002",
                        severity="critical",
                        title="Origin reflection with credentials",
                        detail=(
                            "The server reflected the request Origin into "
                            "Access-Control-Allow-Origin and set "
                            "Access-Control-Allow-Credentials: true. Any origin "
                            "(including an attacker's) can read credentialed "
                            "responses -- account-takeover class risk."
                        ),
                        origin=request_origin,
                        evidence={
                            "access-control-allow-origin": acao,
                            "access-control-allow-credentials": "true",
                        },
                        remediation=(
                            "Validate Origin against a strict allowlist before "
                            "reflecting it; never reflect arbitrary origins with "
                            "credentials enabled."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule="CORS005",
                        severity="medium",
                        title="Origin reflection without credentials",
                        detail=(
                            "The server reflected the request Origin without "
                            "credentials. Lower risk, but indicates origin "
                            "validation is reflective rather than allowlist-based."
                        ),
                        origin=request_origin,
                        evidence={"access-control-allow-origin": acao},
                        remediation="Reflect only allowlisted origins.",
                    )
                )

            # CORS007: scheme downgrade trust.
            req_scheme, _ = _scheme_host(request_origin)
            acao_scheme, _ = _scheme_host(acao)
            if acao_scheme == "http" and req_scheme == "http":
                findings.append(
                    Finding(
                        rule="CORS007",
                        severity="medium",
                        title="Insecure (http) origin trusted",
                        detail=(
                            "An http:// origin is trusted. A network attacker "
                            "can spoof an http origin via MITM and abuse the "
                            "CORS grant."
                        ),
                        origin=request_origin,
                        evidence={"access-control-allow-origin": acao},
                        remediation="Trust only https:// origins.",
                    )
                )

        elif request_origin:
            reason = _looks_like_loose_match(request_origin, acao)
            if reason:
                findings.append(
                    Finding(
                        rule="CORS006",
                        severity="high" if credentials else "medium",
                        title="Loose origin matching (prefix/suffix/substring)",
                        detail=(
                            "The trusted origin appears to be matched by a "
                            "substring/prefix/suffix rule rather than an exact "
                            "comparison: " + reason + ". Attackers register "
                            "lookalike domains (trusted.com.evil.com or "
                            "eviltrusted.com) to satisfy such checks."
                        ),
                        origin=request_origin,
                        evidence={"access-control-allow-origin": acao},
                        remediation=(
                            "Match origins by exact, fully-parsed host "
                            "comparison against an allowlist."
                        ),
                    )
                )

    # CORS008: dangerous methods + credentials.
    if methods_vals and credentials:
        joined = ",".join(methods_vals).upper()
        dangerous = [m for m in ("PUT", "DELETE", "PATCH") if m in joined]
        if dangerous:
            findings.append(
                Finding(
                    rule="CORS008",
                    severity="medium",
                    title="State-changing methods allowed with credentials",
                    detail=(
                        "Access-Control-Allow-Methods permits "
                        + ", ".join(dangerous)
                        + " together with credentials. Combined with a weak "
                        "origin check this enables cross-origin state changes."
                    ),
                    origin=request_origin,
                    evidence={"access-control-allow-methods": ",".join(methods_vals)},
                    remediation=(
                        "Restrict allowed methods to what the endpoint needs "
                        "and ensure strict origin validation."
                    ),
                )
            )

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings


def analyze_config(config: Dict[str, object]) -> List[Finding]:
    """Analyze a declarative CORS config (e.g. parsed from app config/JSON).

    Recognized keys (case-insensitive): allowed_origins / origins (str or list),
    allow_credentials / credentials (bool-ish), allowed_methods / methods.

    Raises TypeError if *config* is not a dict-like mapping.
    """
    if config is None:
        raise TypeError("config must be a dict, got None")
    if not isinstance(config, dict):
        raise TypeError(
            "config must be a dict, got {}".format(type(config).__name__)
        )
    norm = {str(k).strip().lower(): v for k, v in config.items()}

    origins_raw = norm.get("allowed_origins", norm.get("origins", []))
    if isinstance(origins_raw, str):
        origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
    elif isinstance(origins_raw, (list, tuple)):
        origins = [str(o).strip() for o in origins_raw]
    else:
        origins = []

    cred_raw = norm.get("allow_credentials", norm.get("credentials", False))
    if isinstance(cred_raw, str):
        credentials = cred_raw.strip().lower() in ("true", "1", "yes", "on")
    else:
        credentials = bool(cred_raw)

    methods_raw = norm.get("allowed_methods", norm.get("methods", []))
    if isinstance(methods_raw, str):
        methods = [m.strip() for m in methods_raw.split(",") if m.strip()]
    elif isinstance(methods_raw, (list, tuple)):
        methods = [str(m).strip() for m in methods_raw]
    else:
        methods = []

    findings: List[Finding] = []
    origin_set_lower = {o.lower() for o in origins}

    if "*" in origins:
        if credentials:
            findings.append(
                Finding(
                    rule="CORS001",
                    severity="critical",
                    title="Wildcard origin combined with credentials (config)",
                    detail=(
                        "Config allows origin '*' while credentials are enabled. "
                        "This is the highest-risk CORS misconfiguration."
                    ),
                    evidence={"allowed_origins": "*", "allow_credentials": "true"},
                    remediation="Replace '*' with an explicit allowlist; disable credentials for public endpoints.",
                )
            )
        else:
            findings.append(
                Finding(
                    rule="CORS003",
                    severity="low",
                    title="Wildcard origin (config, no credentials)",
                    detail="Config allows origin '*' without credentials.",
                    evidence={"allowed_origins": "*"},
                    remediation="Confirm the resource is intended to be fully public.",
                )
            )

    if "null" in origin_set_lower:
        findings.append(
            Finding(
                rule="CORS004",
                severity="high" if credentials else "medium",
                title="'null' origin allowlisted (config)",
                detail="Config explicitly trusts the 'null' origin, which is attacker-forgeable.",
                evidence={"allowed_origins": "null"},
                remediation="Remove 'null' from the origin allowlist.",
            )
        )

    for o in origins:
        scheme, _ = _scheme_host(o)
        if scheme == "http":
            findings.append(
                Finding(
                    rule="CORS007",
                    severity="medium",
                    title="Insecure (http) origin in allowlist (config)",
                    detail="Config allowlists an http:// origin, spoofable by a network attacker.",
                    origin=o,
                    evidence={"allowed_origin": o},
                    remediation="Allow only https:// origins.",
                )
            )

    if credentials and methods:
        joined = ",".join(methods).upper()
        dangerous = [m for m in ("PUT", "DELETE", "PATCH") if m in joined]
        if dangerous:
            findings.append(
                Finding(
                    rule="CORS008",
                    severity="medium",
                    title="State-changing methods with credentials (config)",
                    detail="Config permits " + ", ".join(dangerous) + " with credentials enabled.",
                    evidence={"allowed_methods": ",".join(methods)},
                    remediation="Restrict methods and ensure strict origin validation.",
                )
            )

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings
