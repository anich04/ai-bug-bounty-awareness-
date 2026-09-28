"""Deterministic policy checks. A decision is not a tool execution permit."""

from dataclasses import asdict, dataclass
import math
import time
from urllib.parse import urljoin
from uuid import uuid4

from .policy import (ACTIONS, HTTP_ACTIONS, METHODS, SAFE_METHODS, SENSITIVE_ACTIONS, PolicyError,
                     Program, Target, normalize_target)
from .programs import ProgramStore


@dataclass(frozen=True)
class Check:
    allowed: bool
    reason: str
    rule_ids: tuple[str, ...] = ()


def target_is_in_scope(program: Program, target: str | Target, *, now: float | None = None) -> Check:
    now = time.time() if now is None else now
    if not math.isfinite(now) or now < 0:
        return Check(False, "invalid_clock")
    if program.authorization_status != "confirmed":
        return Check(False, "ambiguous_authorization")
    if now >= program.valid_until:
        return Check(False, "expired_policy")
    try:
        target = normalize_target(target) if isinstance(target, str) else normalize_target(target.display)
    except (PolicyError, AttributeError):
        return Check(False, "invalid_or_ambiguous_target")
    excluded = tuple(rule.id for rule in program.rules if rule.effect == "exclude" and rule.matches(target, conservative=True))
    if excluded:
        return Check(False, "explicit_exclusion", excluded)
    included = tuple(rule.id for rule in program.rules if rule.effect == "include" and rule.matches(target))
    return Check(bool(included), "included" if included else "unknown_or_insufficiently_specified_target", included)


def action_is_allowed(program: Program, action: str, method: str | None = None) -> Check:
    if action not in ACTIONS:
        return Check(False, "unknown_action")
    policy = next((item for item in program.actions if item.action == action), None)
    if policy is None or not policy.allowed:
        return Check(False, "action_not_authorized")
    if action in HTTP_ACTIONS and method is None:
        return Check(False, "explicit_http_method_required")
    if method is not None and method not in METHODS:
        return Check(False, "unknown_http_method")
    if policy.methods is not None and method not in policy.methods:
        return Check(False, "http_method_not_authorized")
    return Check(True, "action_authorized")


def requires_human_approval(program: Program, action: str, method: str | None = None,
                            *, require_all: bool = True) -> bool:
    policy = next((item for item in program.actions if item.action == action), None)
    return (require_all or program.authorization_status != "confirmed" or policy is None or
            policy.requires_approval or action in SENSITIVE_ACTIONS or
            (method is not None and method not in SAFE_METHODS))


def rate_limit_allows(connection, program: Program, *, now: float,
                      consume: bool = False) -> Check:
    """Sliding-window program-wide budget; caller must hold a write transaction.

    Consumption reserves one unit only; it grants no target/action authorization.
    No cleanup here: policy edits must not erase usage or enable a window reset.
    """
    if not math.isfinite(now) or now < 0:
        return Check(False, "invalid_clock")
    state = connection.execute("SELECT last_seen FROM rate_state WHERE program_id=?", (program.id,)).fetchone()
    if state is not None and now < state[0]:
        return Check(False, "clock_moved_backwards")
    connection.execute("INSERT INTO rate_state VALUES (?, ?) ON CONFLICT(program_id) DO UPDATE SET last_seen=excluded.last_seen", (program.id, now))
    count = connection.execute("SELECT COUNT(*) FROM rate_events WHERE program_id=? AND at>?", (program.id, now - program.window_seconds)).fetchone()[0]
    if count >= program.requests:
        return Check(False, "rate_limit_exceeded")
    if consume:
        connection.execute("INSERT INTO rate_events(program_id,at) VALUES (?,?)", (program.id, now))
    return Check(True, "rate_budget_available")


class RateLimiter:
    """Transactional budget API; a reservation alone never authorizes an action."""

    def __init__(self, store: ProgramStore):
        self.store = store

    def reserve(self, program_id: str, *, now: float | None = None, consume: bool = True) -> Check:
        with self.store.database.transaction(write=True) as connection:
            program = self.store.read(connection, program_id)
            return rate_limit_allows(connection, program, now=time.time() if now is None else now, consume=consume)


class ScopeGuard:
    def __init__(self, store: ProgramStore, *, require_all_approvals: bool = True):
        self.store = store
        self.require_all_approvals = require_all_approvals

    def check(self, program_id: str, target: str, action: str, *, method: str | None = None,
              now: float | None = None, correlation_id: str | None = None) -> dict:
        now = time.time() if now is None else now
        with self.store.database.transaction(write=True) as connection:
            program = self.store.read(connection, program_id)
            scope = target_is_in_scope(program, target, now=now)
            action_check = action_is_allowed(program, action, method)
            if scope.allowed and action in HTTP_ACTIONS and normalize_target(target).scheme is None:
                action_check = Check(False, "http_action_requires_url")
            approval = requires_human_approval(program, action, method, require_all=self.require_all_approvals)
            rate = rate_limit_allows(connection, program, now=now) if scope.allowed and action_check.allowed else Check(False, "not_evaluated")
            reason = next((item.reason for item in (scope, action_check, rate) if not item.allowed), None)
            status = "BLOCKED" if reason else ("WAITING_FOR_HUMAN_APPROVAL" if approval else "POLICY_ALLOWED")
            reason = reason or ("human_approval_required" if approval else "policy_checks_passed")
            try:
                normalized = normalize_target(target)
            except PolicyError:
                normalized = None
            correlation_id = correlation_id or str(uuid4())
            self.store.audit(connection, program, "scope_check", status, reason, correlation_id,
                             normalized.host if normalized else None, action if action in ACTIONS else "unknown")
            return {"ok": status != "BLOCKED", "status": status, "reason": reason,
                    "program_id": program.id, "policy_revision": program.revision,
                    "target": normalized.display if normalized else None,
                    "scope": asdict(scope), "action": asdict(action_check), "rate_limit": asdict(rate),
                    "requires_human_approval": approval, "execution_enabled": False,
                    "correlation_id": correlation_id}

    def check_redirect(self, program_id: str, source: str, location: str, action: str,
                       *, method: str | None = None, now: float | None = None,
                       correlation_id: str | None = None) -> dict:
        # Source and destination both pass the guard; no authorization is inherited.
        correlation_id = correlation_id or str(uuid4())
        first = self.check(program_id, source, action, method=method, now=now, correlation_id=correlation_id)
        if first["status"] == "BLOCKED":
            return first
        try:
            source_target = normalize_target(source)
            if source_target.scheme is None or not location or not location.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in location) or "\\" in location:
                raise PolicyError("Invalid redirect")
            # Validate the raw relative path before urljoin can remove dot segments.
            from urllib.parse import urlsplit
            from .policy import path_name
            parsed = urlsplit(location)
            if parsed.path:
                path_name(parsed.path if parsed.path.startswith("/") else "/" + parsed.path)
            destination = urljoin(source, location)
            normalize_target(destination)
        except (PolicyError, ValueError):
            return self.check(program_id, "", action, method=method, now=now, correlation_id=correlation_id)
        return self.check(program_id, destination, action, method=method, now=now, correlation_id=correlation_id)
