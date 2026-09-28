"""Strict policy contracts and conservative, DNS-free target normalization."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit


class PolicyError(ValueError):
    pass


ACTIONS = frozenset({"discover_assets", "resolve_dns", "probe_http", "collect_urls",
                     "parse_javascript", "analyze_http", "compare_responses", "save_artifact",
                     "validate_candidate", "report_submission", "state_change",
                     "high_volume", "sensitive_account"})
SENSITIVE_ACTIONS = frozenset({"report_submission", "state_change", "high_volume", "sensitive_account"})
METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
HTTP_ACTIONS = frozenset({"probe_http", "collect_urls", "validate_candidate"})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def fields(value, required: set[str], optional: set[str] = frozenset()) -> None:
    require(type(value) is dict, "Policy objects must be JSON objects")
    require(required <= value.keys() and value.keys() <= required | optional,
            "Missing or unknown policy fields")


def identifier(value) -> str:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value) is not None,
            "Invalid policy identifier")
    return value


def host_name(value: str) -> str:
    require(type(value) is str and bool(value) and value.isascii(), "Host must be nonempty ASCII; use explicit punycode for IDNs")
    value = value.lower()
    # Exactly one terminal DNS dot is canonicalized. IPv6 zone IDs are rejected.
    require("%" not in value, "IPv6 zones and encoded hosts are unsupported")
    if ":" in value:
        try:
            return str(ipaddress.IPv6Address(value))
        except ValueError:
            raise PolicyError("Invalid IPv6 host") from None
    value = value[:-1] if value.endswith(".") else value
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    # Browser legacy integer/octal/hex IPv4 interpretations must not match DNS rules.
    require(not re.fullmatch(r"[0-9.]+", value) and not re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", value),
            "Noncanonical numeric host is unsupported")
    require(len(value) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                                     for part in value.split(".")), "Invalid DNS host")
    return value


def path_name(value: str) -> str:
    require(type(value) is str and value.startswith("/"), "Paths must be absolute")
    # Reject ambiguous encodings instead of guessing the target server's decoder.
    require(re.fullmatch(r"/[A-Za-z0-9_./~!-]*", value) is not None,
            "Unsupported or ambiguous path encoding")
    require("//" not in value and all(not part.endswith(".") for part in value.split("/")),
            "Ambiguous path segments are blocked")
    return value


@dataclass(frozen=True)
class Target:
    host: str
    scheme: str | None = None
    port: int | None = None
    path: str | None = None

    @property
    def display(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.scheme:
            return f"{self.scheme}://{host}:{self.port}{self.path}"
        return host + (f":{self.port}" if self.port is not None else "")


def normalize_target(value: str) -> Target:
    require(type(value) is str and 0 < len(value) <= 8192, "Invalid target")
    require(value.isascii() and not any(ord(c) <= 32 or ord(c) == 127 for c in value),
            "Whitespace, control characters and Unicode targets are blocked")
    require("\\" not in value and "#" not in value, "Backslashes and URL fragments are blocked")
    is_url = "://" in value
    try:
        parsed = urlsplit(value if is_url else "//" + value)
        require(not parsed.username and not parsed.password and "@" not in parsed.netloc,
                "URL credentials are blocked")
        authority_pattern = r"\[[0-9A-Fa-f:]+\](?::[0-9]+)?" if parsed.netloc.startswith("[") else r"[A-Za-z0-9.-]+(?::[0-9]+)?"
        require(re.fullmatch(authority_pattern, parsed.netloc) is not None, "Ambiguous URL authority is blocked")
        require(parsed.hostname is not None, "Missing host")
        host = host_name(parsed.hostname)
        port = parsed.port
        require(not parsed.netloc.endswith(":"), "Empty port is blocked")
        require(port is None or 1 <= port <= 65535, "Invalid port")
        if is_url:
            require(parsed.scheme.lower() in {"http", "https"}, "Only HTTP and HTTPS URLs are supported")
            scheme = parsed.scheme.lower()
            return Target(host, scheme, port if port is not None else (443 if scheme == "https" else 80),
                          path_name(parsed.path or "/"))
        require(not parsed.path and not parsed.query and "?" not in value, "Bare targets must be hosts or host:port")
        return Target(host, port=port)
    except ValueError as error:
        if isinstance(error, PolicyError):
            raise
        raise PolicyError("Malformed target or port") from None


def timestamp(value: str) -> float:
    require(type(value) is str, "valid_until must be an ISO 8601 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None, "valid_until must include a timezone")
        return result.timestamp()
    except (ValueError, OverflowError):
        raise PolicyError("Invalid policy expiry timestamp") from None


@dataclass(frozen=True)
class ScopeRule:
    id: str
    effect: str
    host: str
    schemes: tuple[str, ...] | None
    ports: tuple[int, ...] | None
    path_prefix: str | None

    def matches(self, target: Target, *, conservative: bool = False) -> bool:
        if self.host.startswith("*."):
            suffix = self.host[2:]
            host_match = target.host != suffix and target.host.endswith("." + suffix)
        else:
            host_match = target.host == self.host
        if not host_match:
            return False
        for actual, choices in ((target.scheme, self.schemes), (target.port, self.ports)):
            if choices is not None and ((actual is None and not conservative) or
                                        (actual is not None and actual not in choices)):
                return False
        if self.path_prefix is not None:
            if target.path is None:
                return conservative
            prefix = self.path_prefix.rstrip("/")
            path = target.path
            if conservative:
                prefix, path = prefix.lower(), path.lower()
            if path != prefix and not path.startswith(prefix + "/"):
                return False
        return True


@dataclass(frozen=True)
class ActionPolicy:
    action: str
    allowed: bool
    requires_approval: bool
    methods: tuple[str, ...] | None


@dataclass(frozen=True)
class Program:
    id: str
    name: str
    authorization_status: str
    authorization_source: str
    valid_until: float
    rules: tuple[ScopeRule, ...]
    actions: tuple[ActionPolicy, ...]
    requests: int
    window_seconds: int
    document: str
    revision: str

    @classmethod
    def from_dict(cls, value) -> "Program":
        fields(value, {"id", "name", "authorization_status", "authorization_source", "valid_until", "scope", "actions", "rate_limit"})
        identifier(value["id"])
        for key in ("name", "authorization_source"):
            require(type(value[key]) is str and 0 < len(value[key]) <= 2048 and value[key].strip() == value[key],
                    "Name and authorization source must be nonempty text")
        require(value["authorization_status"] in ("confirmed", "ambiguous"), "Invalid authorization status")
        expiry = timestamp(value["valid_until"])
        require(type(value["scope"]) is list and 0 < len(value["scope"]) <= 1000, "Scope must contain 1 to 1000 rules")
        rules = []
        for item in value["scope"]:
            fields(item, {"id", "effect", "host"}, {"schemes", "ports", "path_prefix"})
            identifier(item["id"])
            require(item["effect"] in ("include", "exclude"), "Invalid scope effect")
            raw_host = item["host"]
            require(type(raw_host) is str, "Invalid rule host")
            wildcard = raw_host.startswith("*.")
            host = host_name(raw_host[2:] if wildcard else raw_host)
            if wildcard:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    require("." in host, "Wildcard suffix must have multiple DNS labels")
                else:
                    raise PolicyError("IP wildcards are unsupported")
                host = "*." + host
            schemes, ports = item.get("schemes"), item.get("ports")
            for key, choices in (("schemes", schemes), ("ports", ports)):
                if key in item:
                    require(type(choices) is list and bool(choices), "Rule constraints must be nonempty arrays")
                    if key == "schemes":
                        require(all(type(s) is str and s in {"http", "https"} for s in choices), "Invalid scheme constraint")
                    else:
                        require(all(type(p) is int and 1 <= p <= 65535 for p in choices), "Invalid port constraint")
                    require(len(set(choices)) == len(choices), "Duplicate rule constraints")
            path = path_name(item["path_prefix"]) if "path_prefix" in item else None
            rules.append(ScopeRule(item["id"], item["effect"], host,
                                   tuple(schemes) if schemes is not None else None,
                                   tuple(ports) if ports is not None else None, path))
        require(len({r.id for r in rules}) == len(rules), "Duplicate scope rule IDs")
        actions = []
        require(type(value["actions"]) is list and len(value["actions"]) <= len(ACTIONS), "Invalid action policies")
        for item in value["actions"]:
            fields(item, {"action", "allowed", "requires_approval"}, {"methods"})
            require(type(item["action"]) is str and item["action"] in ACTIONS, "Unknown action policy")
            require(type(item["allowed"]) is bool and type(item["requires_approval"]) is bool, "Action flags must be booleans")
            methods = item.get("methods")
            if "methods" in item:
                require(type(methods) is list and bool(methods) and all(type(m) is str and m in METHODS for m in methods), "Invalid HTTP methods")
                require(len(set(methods)) == len(methods), "Duplicate HTTP methods")
            actions.append(ActionPolicy(item["action"], item["allowed"], item["requires_approval"],
                                        tuple(methods) if methods is not None else None))
        require(len({a.action for a in actions}) == len(actions), "Duplicate action policies")
        rate = value["rate_limit"]
        fields(rate, {"requests", "window_seconds"})
        require(type(rate["requests"]) is int and 1 <= rate["requests"] <= 100000 and
                type(rate["window_seconds"]) is int and 1 <= rate["window_seconds"] <= 86400,
                "Rate limit must use bounded positive integers")
        document = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return cls(value["id"], value["name"], value["authorization_status"], value["authorization_source"],
                   expiry, tuple(rules), tuple(actions), rate["requests"], rate["window_seconds"],
                   document, hashlib.sha256(document.encode()).hexdigest())


def load_program(text: str) -> Program:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON keys are blocked")
            result[key] = value
        return result
    require(type(text) is str and len(text) <= 1_000_000, "Policy document is too large")
    try:
        return Program.from_dict(json.loads(text, object_pairs_hook=unique))
    except (json.JSONDecodeError, RecursionError):
        raise PolicyError("Invalid policy JSON") from None
