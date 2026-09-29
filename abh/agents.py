"""Built-in deterministic agents. Inputs are data, never tool instructions."""

from dataclasses import dataclass
import json
from types import MappingProxyType
from typing import Protocol

from .agent_contracts import validate_input
from .policy import PolicyError, Program, normalize_target
from .scope import target_is_in_scope


@dataclass(frozen=True)
class AgentContext:
    job_id: str
    target: str
    program: Program
    now: float
    input_sha: str


class Agent(Protocol):
    name: str
    def run(self, context: AgentContext, payload: dict) -> dict: ...


class BaseAgent:
    name = ""

    def run(self, context: AgentContext, payload: dict) -> dict:
        validate_input(self.name, payload)
        data, uncertainty = self.analyze(context, payload["data"])
        return {"version": 1, "agent": self.name, "job_id": context.job_id,
                "policy_revision": context.program.revision, "input_sha": context.input_sha,
                "kind": "offline_agent_result", "data": data, "uncertainty": uncertainty,
                "tool_executed": False, "network_requests": 0, "finding_created": False, "report_submitted": False}

    def analyze(self, context: AgentContext, data: dict) -> tuple[dict, list[str]]:
        raise NotImplementedError


class Scout(BaseAgent):
    name = "scout"

    def analyze(self, context, data):
        policy = json.loads(context.program.document)
        return {"authorization_status": policy["authorization_status"],
                "includes": [rule for rule in policy["scope"] if rule["effect"] == "include"],
                "exclusions": [rule for rule in policy["scope"] if rule["effect"] == "exclude"],
                "actions": policy["actions"], "rate_limit": policy["rate_limit"], "valid_until": policy["valid_until"]}, [
                    "Summary of human-supplied structured policy only; authorization source has not been independently verified."]


class Mapper(BaseAgent):
    name = "mapper"
    field = "assets"

    def analyze(self, context, data):
        items = []
        for index, value in enumerate(data[self.field]):
            try:
                # Query-sensitive collection belongs to later adapters; never silently drop inputs.
                if "?" in value:
                    raise PolicyError("Unsupported query")
                target = normalize_target(value)
                if self.name == "crawler" and target.scheme is None:
                    raise PolicyError("URL required")
                check = target_is_in_scope(context.program, target, now=context.now)
                items.append({"index": index, "target": target.display, "in_scope": check.allowed, "reason": check.reason})
            except PolicyError:
                items.append({"index": index, "target": None, "in_scope": False, "reason": "invalid_or_unsupported_input"})
        return {"items": items}, ["Classified supplied identifiers only. No discovery, DNS resolution, HTTP request or live observation occurred."]


class Crawler(Mapper):
    name = "crawler"
    field = "urls"


class Validator(BaseAgent):
    name = "validator"

    def analyze(self, context, data):
        return {"status": "needs_evidence", "supplied_facts": data["observations"], "hypothesis": data["hypothesis"],
                "checks": {"real": "unknown", "reproducible": "unknown",
                           "in_scope": target_is_in_scope(context.program, context.target, now=context.now).allowed,
                           "security_relevant": "unknown", "duplicate": "unknown", "evidence_sufficient": False}}, [
                               "Facts and evidence identifiers are unverified supplied data.",
                               "Evidence storage, reproducible validation and deduplication are not implemented in this phase."]


class Reporter(BaseAgent):
    name = "reporter"

    def analyze(self, context, data):
        return {"status": "needs_validated_evidence", "questions": [
            {**question, "answer": None, "evidence": []} for question in data["questions"]]}, [
                "Exact supplied questions are preserved. Answers remain empty until supported by validated evidence."]


HANDLERS = MappingProxyType({agent.name: agent for agent in (Scout(), Mapper(), Crawler(), Validator(), Reporter())})
