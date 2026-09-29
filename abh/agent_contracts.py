"""Versioned, bounded contracts for built-in offline agents."""

from dataclasses import asdict, dataclass
import hashlib
import json
from types import MappingProxyType

from .policy import identifier


class ContractError(ValueError):
    pass


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def keys(value, expected: set[str]) -> None:
    ensure(type(value) is dict and value.keys() == expected, "Missing or unknown contract fields")


def text(value, *, maximum: int = 4096) -> None:
    ensure(type(value) is str and 0 < len(value) <= maximum and "\x00" not in value, "Invalid or oversized contract text")


def sequence(value) -> None:
    ensure(type(value) is list and len(value) <= 100, "Contract lists must contain at most 100 items")


def canonical(value) -> str:
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise ContractError("Contract must be finite JSON data") from None
    ensure(len(result.encode()) <= 131072, "Agent contract exceeds 128 KiB")
    return result


def digest(document: str) -> str:
    return hashlib.sha256(document.encode()).hexdigest()


@dataclass(frozen=True)
class Charter:
    name: str
    action: str
    method: str | None
    responsibility: str
    limitations: tuple[str, ...]
    input_fields: tuple[str, ...]
    next_agents: tuple[str, ...]
    contract_version: int = 1

    def describe(self) -> dict:
        return asdict(self)


REGISTRY = MappingProxyType({
    "scout": Charter("scout", "review_policy", None, "Summarize the stored structured program policy without inventing permission.",
                     ("No natural-language policy interpretation", "No scope changes"), (), ("mapper",)),
    "mapper": Charter("mapper", "discover_assets", None, "Normalize and classify supplied asset identifiers against current scope.",
                      ("No DNS or asset discovery calls", "Unknown assets remain unauthorized"), ("assets",), ("crawler",)),
    "crawler": Charter("crawler", "collect_urls", "GET", "Normalize and classify supplied endpoint URLs against current scope.",
                       ("No crawling or HTTP requests", "No authentication inference"), ("urls",), ("validator",)),
    "validator": Charter("validator", "validate_candidate", "GET", "Separate supplied facts, hypothesis and uncertainty in a preliminary review.",
                         ("No reproduction or evidence verification", "Cannot declare a validated vulnerability"),
                         ("observations", "hypothesis"), ("reporter",)),
    "reporter": Charter("reporter", "draft_report", None, "Preserve exact program questions in an incomplete report scaffold.",
                        ("No unsupported answers", "No report submission or validated finding storage"), ("questions",), ()),
})


def charter(name: str) -> Charter:
    ensure(type(name) is str and name in REGISTRY, "Agent is not implemented in this phase")
    return REGISTRY[name]


def validate_input(agent: str, value) -> str:
    definition = charter(agent)
    keys(value, {"version", "data"})
    ensure(type(value["version"]) is int and value["version"] == 1, "Unsupported agent input version")
    data = value["data"]
    keys(data, set(definition.input_fields))
    if agent in {"mapper", "crawler"}:
        values = data[definition.input_fields[0]]
        sequence(values)
        for item in values:
            text(item, maximum=8192)
    elif agent == "validator":
        text(data["hypothesis"])
        sequence(data["observations"])
        ids = set()
        for observation in data["observations"]:
            keys(observation, {"id", "fact", "evidence_refs"})
            identifier(observation["id"])
            ensure(observation["id"] not in ids, "Duplicate observation ID")
            ids.add(observation["id"])
            text(observation["fact"])
            sequence(observation["evidence_refs"])
            for reference in observation["evidence_refs"]:
                identifier(reference)
    elif agent == "reporter":
        sequence(data["questions"])
        ids = set()
        for question in data["questions"]:
            keys(question, {"id", "label", "required"})
            identifier(question["id"])
            ensure(question["id"] not in ids, "Duplicate question ID")
            ids.add(question["id"])
            text(question["label"])
            ensure(type(question["required"]) is bool, "Question required flag must be boolean")
    return canonical(value)


def load_input(agent: str, document: str) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            ensure(key not in value, "Duplicate agent input key")
            value[key] = item
        return value
    ensure(type(document) is str and len(document.encode()) <= 131072, "Agent input exceeds 128 KiB")
    try:
        value = json.loads(document, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        raise ContractError("Invalid agent input JSON") from None
    validate_input(agent, value)
    return value


def validate_output(value, *, agent: str, job_id: str, revision: str, input_sha: str) -> str:
    keys(value, {"version", "agent", "job_id", "policy_revision", "input_sha", "kind", "data",
                 "uncertainty", "tool_executed", "network_requests", "finding_created", "report_submitted"})
    ensure(type(value["version"]) is int and value["version"] == 1, "Unsupported agent output version")
    ensure(value["agent"] == agent and value["job_id"] == job_id and value["policy_revision"] == revision and value["input_sha"] == input_sha,
           "Agent output provenance mismatch")
    ensure(value["kind"] == "offline_agent_result" and value["tool_executed"] is False and
           type(value["network_requests"]) is int and value["network_requests"] == 0 and
           value["finding_created"] is False and value["report_submitted"] is False,
           "Agent output claims unsupported execution")
    sequence(value["uncertainty"])
    for item in value["uncertainty"]:
        text(item)
    data = value["data"]
    if agent == "scout":
        keys(data, {"authorization_status", "includes", "exclusions", "actions", "rate_limit", "valid_until"})
        ensure(data["authorization_status"] in ("confirmed", "ambiguous"), "Invalid authorization summary")
        # Program is already validated; bounded serialization below limits aggregate size.
        ensure(all(type(data[k]) is list for k in ("includes", "exclusions", "actions")), "Invalid policy summary lists")
        keys(data["rate_limit"], {"requests", "window_seconds"})
        text(data["valid_until"])
    elif agent in {"mapper", "crawler"}:
        keys(data, {"items"})
        sequence(data["items"])
        for item in data["items"]:
            keys(item, {"index", "target", "in_scope", "reason"})
            ensure(type(item["index"]) is int and item["index"] >= 0 and type(item["in_scope"]) is bool,
                   "Invalid inventory item")
            ensure(item["target"] is None or type(item["target"]) is str, "Invalid inventory target")
            text(item["reason"])
    elif agent == "validator":
        keys(data, {"status", "supplied_facts", "hypothesis", "checks"})
        ensure(data["status"] == "needs_evidence", "Preliminary validator cannot validate a finding")
        sequence(data["supplied_facts"])
        text(data["hypothesis"])
        keys(data["checks"], {"real", "reproducible", "in_scope", "security_relevant", "duplicate", "evidence_sufficient"})
        ensure(all(data["checks"][key] == "unknown" for key in ("real", "reproducible", "security_relevant", "duplicate")) and
               type(data["checks"]["in_scope"]) is bool and data["checks"]["evidence_sufficient"] is False,
               "Unsupported validation assertion")
    elif agent == "reporter":
        keys(data, {"status", "questions"})
        ensure(data["status"] == "needs_validated_evidence", "Reporter cannot produce a final report yet")
        sequence(data["questions"])
        for question in data["questions"]:
            keys(question, {"id", "label", "required", "answer", "evidence"})
            identifier(question["id"])
            text(question["label"])
            ensure(type(question["required"]) is bool and question["answer"] is None and question["evidence"] == [],
                   "Unsupported report answer")
    else:
        raise ContractError("Agent is not implemented")
    return canonical(value)
