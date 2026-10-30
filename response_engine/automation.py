"""Deterministic automated-response policy: which alerts get which closed
action, in which execution mode -- and the incident-level response status a
consumer derives from the outcome.

This module decides; it never executes. ``evaluate_policy`` is a pure
function of (alert record, translated command action, policy set, global
mode). The consuming backend (panopticon-manager) persists the decision,
runs its simulation adapter, and stages/authorizes the command through its
existing path. See docs/AUTOMATED_RESPONSE.md.

Guardrails enforced here, in code, regardless of policy configuration:

  - The alert never chooses the action or the target. The command action
    comes only from ``translate_recommendation``; a policy applies only when
    its own declared action equals that translated action.
  - ``auto`` is honoured only for AUTO_SAFE actions (``classify_tier``).
    KILL_PROCESS, QUARANTINE_FILE, ISOLATE_HOST, ... are downgraded to
    ``approval`` -- the locked tier decisions are not weakened by a policy.
  - A malformed alert, an action outside the closed set, or an alert raised
    by the response executor's own activity is ``denied``.
  - A policy gate (level, confidence, evidence, detection source, host) that
    fails demotes the decision to ``record``: evidence is kept, nothing runs.
    A missing confidence fails a confidence gate; it is never assumed.
  - Global mode ``simulate`` (the default) turns every ``approval`` decision
    (policy-matched or default-tier) into ``simulate``: the intended
    containment is previewed and recorded, and no command is staged. Real
    execution needs global mode ``enforce`` *and* an analyst approval.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from response_engine.contract import ACTIONS, Action
from response_engine.policy import Tier, classify_tier

PolicyMode = Literal["record", "simulate", "approval", "auto"]
DecisionMode = Literal["record", "simulate", "approval", "auto", "denied"]
GlobalMode = Literal["simulate", "enforce"]

DEFAULT_GLOBAL_MODE: GlobalMode = "simulate"

# Repeat alerts on the same host/action/target inside this window are not
# answered again when no policy sets its own cooldown.
DEFAULT_TIER_COOLDOWN_SECONDS = 300

# Process command lines/images carrying this marker belong to the response
# executor itself; alerts on them are never answered (response-loop guard).
RESPONSE_EXECUTOR_MARKER = "panopticon-response-executor"

# Command-result detail prefix an executor uses only after it independently
# observed the action's effect (e.g. the target process is gone).
VERIFIED_PREFIX = "verified:"

# Actions whose success means containment, not just investigation.
CONTAINMENT_ACTIONS = frozenset({"KILL_PROCESS", "QUARANTINE_FILE", "ISOLATE_HOST"})

_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


class PolicyMatch(BaseModel):
    """Which alerts a policy applies to. Any listed criterion matching is
    enough; at least one criterion is required (no implicit catch-all)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    rule_ids: tuple[str, ...] = ()
    rule_prefixes: tuple[str, ...] = ()
    mitre_tactics: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _non_empty(self) -> "PolicyMatch":
        if not (self.rule_ids or self.rule_prefixes or self.mitre_tactics):
            raise ValueError("a policy match needs at least one criterion")
        return self

    def matches(self, alert: Mapping[str, Any]) -> bool:
        rule_id = alert.get("rule_id")
        tactic = alert.get("mitre_tactic")
        return (
            rule_id in self.rule_ids
            or any(isinstance(rule_id, str) and rule_id.startswith(p) for p in self.rule_prefixes)
            or (isinstance(tactic, str) and tactic in self.mitre_tactics)
        )


class ResponsePolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    policy_id: str
    description: str = Field(max_length=300)
    match: PolicyMatch
    action: Action
    mode: PolicyMode
    min_level: int = Field(default=0, ge=0, le=16)
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    required_evidence: tuple[str, ...] = ()
    detection_sources: tuple[str, ...] = ("rule", "stateful", "correlation")
    host_allowlist: tuple[str, ...] = ()
    cooldown_seconds: int = Field(default=300, ge=0, le=86_400)

    @model_validator(mode="after")
    def _valid_id(self) -> "ResponsePolicy":
        if not _POLICY_ID.match(self.policy_id):
            raise ValueError("policy_id must be lowercase kebab-case")
        return self


class PolicyDecision(BaseModel):
    """The audited outcome of evaluating one alert. ``simulate`` asks the
    consumer to run its no-side-effect simulation adapter; ``auto_execute``
    permits immediate authorization as the system actor."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    policy_id: str
    action: str | None
    mode: DecisionMode
    global_mode: GlobalMode
    simulate: bool
    auto_execute: bool
    cooldown_seconds: int
    reasons: tuple[str, ...]


DEFAULT_POLICIES: tuple[ResponsePolicy, ...] = (
    ResponsePolicy(
        policy_id="contain-download-cradle",
        description="PowerShell download cradle with high rule confidence: terminate the exact "
        "process instance after analyst approval.",
        match=PolicyMatch(rule_ids=("DET-PROC-012",)),
        action="KILL_PROCESS",
        mode="approval",
        min_level=12,
        min_confidence=0.8,
        required_evidence=("process.command_line",),
    ),
    ResponsePolicy(
        policy_id="contain-reverse-shell",
        description="Linux /dev/tcp reverse shell: terminate the exact process instance after "
        "analyst approval.",
        match=PolicyMatch(rule_ids=("DET-LNX-001",)),
        action="KILL_PROCESS",
        mode="approval",
        min_level=12,
        min_confidence=0.85,
        required_evidence=("process.command_line",),
    ),
    ResponsePolicy(
        policy_id="contain-credential-theft",
        description="Credential-access tooling: terminate the exact process instance after "
        "analyst approval.",
        match=PolicyMatch(rule_prefixes=("DET-CRED-",)),
        action="KILL_PROCESS",
        mode="approval",
        min_level=12,
        min_confidence=0.8,
    ),
    ResponsePolicy(
        policy_id="investigate-process",
        description="Read-only process inspection runs automatically.",
        match=PolicyMatch(rule_ids=("DET-PS-010", "DET-INJ-010", "DET-INJ-011", "DET-CRED-010")),
        action="COLLECT_PROCESS_INFO",
        mode="auto",
        cooldown_seconds=60,
    ),
    ResponsePolicy(
        policy_id="isolate-exfiltration",
        description="Host isolation is disruptive and often ambiguous: preview only, then "
        "require approval.",
        match=PolicyMatch(rule_ids=("DET-EXFIL-001",)),
        action="ISOLATE_HOST",
        mode="approval",
        min_level=12,
    ),
)


def _malformed(alert: Any) -> str | None:
    if not isinstance(alert, Mapping):
        return "alert is not an object"
    for key in ("alert_id", "rule_id", "host_id"):
        value = alert.get(key)
        if not isinstance(value, str) or not value.strip():
            return f"alert has no {key}"
    level = alert.get("level")
    if type(level) is not int or not 0 <= level <= 16:
        return "alert level is not an integer in 0..16"
    evidence = alert.get("evidence", {})
    if evidence is not None and not isinstance(evidence, Mapping):
        return "alert evidence is not an object"
    return None


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _gate_failures(policy: ResponsePolicy, alert: Mapping[str, Any]) -> list[str]:
    failures = []
    if alert["level"] < policy.min_level:
        failures.append(f"level {alert['level']} below {policy.min_level}")
    if policy.min_confidence is not None:
        confidence = alert.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            failures.append("alert carries no confidence")
        elif confidence < policy.min_confidence:
            failures.append(f"confidence {confidence} below {policy.min_confidence}")
    evidence = alert.get("evidence") or {}
    for key in policy.required_evidence:
        if evidence.get(key) in (None, "", [], {}):
            failures.append(f"evidence missing {key}")
    if alert.get("detection_source") not in policy.detection_sources:
        failures.append(f"detection source {alert.get('detection_source')!r} not eligible")
    if policy.host_allowlist and alert["host_id"] not in policy.host_allowlist:
        failures.append(f"host {alert['host_id']} not in policy scope")
    return failures


def evaluate_policy(
    alert: Any,
    command_action: str | None,
    *,
    policies: Iterable[ResponsePolicy] = DEFAULT_POLICIES,
    global_mode: str = DEFAULT_GLOBAL_MODE,
) -> PolicyDecision:
    """Decide how to respond to one alert whose recommendation translated to
    ``command_action`` (None when nothing translated). First matching policy
    whose action equals ``command_action`` wins. With no matching policy the
    decision is ``default-tier``: AUTO_SAFE actions auto-execute, everything
    else awaits approval (Manager's behaviour before policies existed) -- or,
    in global mode ``simulate``, is previewed only."""
    if global_mode not in ("simulate", "enforce"):
        # Fail closed on a misconfigured mode: behave as the safe default.
        global_mode = DEFAULT_GLOBAL_MODE

    def decide(policy_id, action, mode, reasons, cooldown=0) -> PolicyDecision:
        return PolicyDecision(
            policy_id=policy_id,
            action=action,
            mode=mode,
            global_mode=global_mode,
            simulate=mode in ("simulate", "approval"),
            auto_execute=mode == "auto",
            cooldown_seconds=cooldown,
            reasons=tuple(reasons),
        )

    problem = _malformed(alert)
    if problem is not None:
        return decide("validation", command_action, "denied", [f"malformed alert: {problem}"])
    if command_action is None:
        return decide("default-tier", None, "record", ["no translatable recommendation"])
    if command_action not in ACTIONS:
        return decide(
            "validation", command_action, "denied", [f"{command_action} is outside the closed set"]
        )
    if any(RESPONSE_EXECUTOR_MARKER in text for text in _strings(alert.get("evidence"))):
        return decide(
            "loop-guard", command_action, "denied",
            ["alert describes the response executor's own activity"],
        )

    tier = classify_tier(command_action)
    reasons: list[str] = []
    policy = next(
        (
            p for p in policies
            if p.match.matches(alert) and p.action == command_action
        ),
        None,
    )
    if policy is None:
        mode = "auto" if tier is Tier.AUTO_SAFE else "approval"
        reasons.append(f"no policy matched; tier {tier.value}")
        if mode == "approval" and global_mode == "simulate":
            mode = "simulate"
            reasons.append("global mode simulate: containment previewed, not staged")
        return decide(
            "default-tier", command_action, mode, reasons, DEFAULT_TIER_COOLDOWN_SECONDS
        )

    reasons.append(f"matched {policy.policy_id}")
    failures = _gate_failures(policy, alert)
    if failures:
        return decide(
            policy.policy_id, command_action, "record",
            reasons + [f"gate failed: {f}" for f in failures], policy.cooldown_seconds,
        )
    mode: str = policy.mode
    if mode == "auto" and tier is not Tier.AUTO_SAFE:
        mode = "approval"
        reasons.append(f"auto downgraded to approval: {command_action} is {tier.value}")
    if mode == "approval" and global_mode == "simulate":
        mode = "simulate"
        reasons.append("global mode simulate: containment previewed, not staged")
    return decide(policy.policy_id, command_action, mode, reasons, policy.cooldown_seconds)


ResponseStatus = Literal[
    "resolved",
    "contained",
    "containment_unverified",
    "containment_failed",
    "response_executing",
    "awaiting_approval",
    "simulated_containment",
    "response_recorded",
    "detected",
]


def derive_response_status(
    actions: Iterable[Mapping[str, Any]], incident_status: str | None = None
) -> ResponseStatus:
    """Collapses an incident's (or alert's) response actions into one status.
    Each item may carry ``action``, ``lifecycle_state`` (response_actions),
    ``command_lifecycle_state``, ``result_detail`` and ``simulation_status``.
    Acknowledging or resolving an incident is reported as ``resolved``, never
    as ``contained``: only a SUCCEEDED containment command is containment,
    and only a verified one is ``contained``."""
    if incident_status in ("resolved", "false_positive"):
        return "resolved"
    found: set[str] = set()
    for item in actions:
        action = item.get("action")
        command = item.get("command_lifecycle_state")
        containment = action in CONTAINMENT_ACTIONS
        if containment and command == "SUCCEEDED":
            detail = item.get("result_detail") or ""
            found.add("contained" if detail.startswith(VERIFIED_PREFIX)
                      else "containment_unverified")
        elif containment and command in ("FAILED", "REJECTED", "INDETERMINATE", "EXPIRED"):
            found.add("containment_failed")
        elif containment and command in ("AUTHORIZED", "DISPATCHED", "ACCEPTED"):
            found.add("response_executing")
        elif containment and item.get("lifecycle_state") == "PENDING":
            found.add("awaiting_approval")
        elif item.get("simulation_status") == "simulated":
            found.add("simulated_containment")
        else:
            found.add("response_recorded")
    for status in (
        "contained",
        "containment_unverified",
        "containment_failed",
        "response_executing",
        "awaiting_approval",
        "simulated_containment",
        "response_recorded",
    ):
        if status in found:
            return status  # type: ignore[return-value]
    return "detected"
