"""Versioned, side-effect-free collection-only triage policy and budget decisions."""

import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from response_engine.contract import Action

COLLECT_ACTIONS = ("COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS", "COLLECT_FILE")
CollectAction = Literal["COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS", "COLLECT_FILE"]
AssetClass = Literal["standard", "critical", "unknown"]
Decision = Literal["auto_dispatch", "skip", "require_approval"]
ARTIFACT_PROTOCOL = "signed-json-v2-resume-v1"
AUTO_TRIAGE_ACTOR = "system/auto-triage"
MAX_ACTIVE_GLOBAL = 128
ARTIFACT_RESERVATION_BYTES = 1048576


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CollectionBudget(Closed):
    # Each action reserves the full native artifact maximum before dispatch. A
    # smaller declared size would not constrain an already-deployed collector.
    reserved_bytes_per_action: StrictInt = Field(default=1048576, ge=1048576, le=1048576)
    max_actions_per_alert: StrictInt = Field(default=3, ge=1, le=3)
    max_bytes_per_alert: StrictInt = Field(default=3145728, ge=1048576, le=3145728)
    endpoint_window_seconds: StrictInt = Field(default=900, ge=60, le=86400)
    max_actions_per_endpoint_window: StrictInt = Field(default=12, ge=1, le=64)
    max_bytes_per_endpoint_window: StrictInt = Field(default=12582912, ge=1048576, le=67108864)
    max_active_per_endpoint: StrictInt = Field(default=3, ge=1, le=8)
    workflow_ttl_seconds: StrictInt = Field(default=300, ge=30, le=900)


class ApprovedFile(Closed):
    platform: Literal["windows", "linux"]
    path: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def exact_native_path(self):
        value = self.path
        if any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in "*?[]"):
            raise ValueError("file allowlist accepts exact paths only")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("file path must be valid UTF-8") from exc
        if self.platform == "linux":
            parts = value.split("/")[1:]
            valid = value.startswith("/") and not value.startswith("//") and "\\" not in value
        else:
            valid = bool(re.match(r"^[A-Za-z]:\\", value)) and "/" not in value
            parts = value[3:].split("\\")
            if any(
                any(c in part for c in '<>:"|')
                or part.endswith((".", " "))
                or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
                for part in parts
            ):
                valid = False
        if not valid or any(part in {"", ".", ".."} for part in parts):
            raise ValueError("file allowlist requires an unambiguous absolute native file path")
        return self


class ActionPolicy(Closed):
    action: CollectAction
    asset_class: AssetClass
    decision: Decision
    file_paths: list[ApprovedFile] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def enforce_automation_boundary(self):
        if self.asset_class != "standard" and self.decision == "auto_dispatch":
            raise ValueError("critical and unclassified endpoints cannot auto-dispatch")
        auto_file = self.action == "COLLECT_FILE" and self.decision == "auto_dispatch"
        if auto_file != bool(self.file_paths):
            raise ValueError("only auto COLLECT_FILE requires an explicit exact-path allowlist")
        paths = [(p.platform, p.path) for p in self.file_paths]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate exact file allowlist path")
        return self


class AutoTriagePolicy(Closed):
    schema_version: Literal["1"]
    rule_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    version: StrictInt = Field(ge=1, le=2147483647)
    enabled: StrictBool = False
    entries: list[ActionPolicy] = Field(min_length=1, max_length=9)
    budget: CollectionBudget = Field(default_factory=CollectionBudget)

    @field_validator("entries")
    @classmethod
    def one_decision_per_action_and_asset_class(cls, values):
        pairs = [(entry.action, entry.asset_class) for entry in values]
        if len(pairs) != len(set(pairs)):
            raise ValueError("duplicate rule action and asset-class policy entry")
        return values


class EndpointCapability(Closed):
    platform: Literal["windows", "linux"]
    recent: StrictBool
    mode: Literal["off", "dry_run", "enforce"]
    implemented_actions: list[Action] = Field(max_length=7)
    allowed_actions: list[Action] = Field(max_length=7)
    authenticated_command_channel: StrictBool
    collection_acceptance_gate: StrictBool
    artifact_protocol: Literal["signed-json-v2-resume-v1"] | None


class BudgetUsage(Closed):
    actions_for_alert: StrictInt = Field(default=0, ge=0)
    bytes_for_alert: StrictInt = Field(default=0, ge=0)
    actions_in_endpoint_window: StrictInt = Field(default=0, ge=0)
    bytes_in_endpoint_window: StrictInt = Field(default=0, ge=0)
    active_for_endpoint: StrictInt = Field(default=0, ge=0)
    active_global: StrictInt = Field(default=0, ge=0)


class TriageDecision(Closed):
    schema_version: Literal["1"] = "1"
    rule_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    policy_version: StrictInt = Field(ge=1, le=2147483647)
    action: CollectAction
    asset_class: AssetClass
    decision: Decision
    reason: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_]+$")


def evaluate(
    policy: AutoTriagePolicy,
    action: CollectAction,
    asset_class: AssetClass,
    endpoint: EndpointCapability,
    usage: BudgetUsage,
    *,
    process_identity_verified: bool = False,
    file_path: str | None = None,
) -> TriageDecision:
    """No implicit approval: capability, target and budget may only restrict policy."""
    if action not in COLLECT_ACTIONS:
        raise ValueError("automatic triage is restricted to the three collection actions")
    if asset_class not in {"standard", "critical", "unknown"}:
        raise ValueError("unrecognized Manager-owned asset classification")

    def result(decision, reason):
        return TriageDecision(
            rule_id=policy.rule_id,
            policy_version=policy.version,
            action=action,
            asset_class=asset_class,
            decision=decision,
            reason=reason,
        )

    if not policy.enabled:
        return result("skip", "rule_disabled")
    entry = next(
        (e for e in policy.entries if e.action == action and e.asset_class == asset_class), None
    )
    if entry is None:
        return result("skip", "no_matching_policy_entry")
    if entry.decision == "skip":
        return result("skip", "policy_skip")
    if not endpoint.recent:
        return result("skip", "capability_report_not_current")
    if action not in endpoint.implemented_actions:
        return result("skip", "action_not_supported")
    if action not in endpoint.allowed_actions:
        return result("skip", "endpoint_policy_denied")
    if endpoint.mode != "enforce":
        return result("skip", "endpoint_not_enforcing")
    if not endpoint.authenticated_command_channel:
        return result("skip", "authenticated_command_channel_required")
    if not endpoint.collection_acceptance_gate:
        return result("skip", "execution_policy_gate_required")
    if endpoint.artifact_protocol != ARTIFACT_PROTOCOL:
        return result("skip", "signed_artifact_delivery_not_supported")
    if action == "COLLECT_PROCESS_INFO" and process_identity_verified is not True:
        return result("skip", "verified_process_identity_required")
    if action == "COLLECT_FILE":
        if not file_path:
            return result("skip", "alert_file_target_missing")
        try:
            ApprovedFile(platform=endpoint.platform, path=file_path)
        except ValueError:
            return result("skip", "alert_file_target_invalid")
        if entry.decision == "auto_dispatch" and not any(
            p.platform == endpoint.platform and p.path == file_path for p in entry.file_paths
        ):
            return result("skip", "alert_file_target_not_allowlisted")
    budget = policy.budget
    checks = (
        (usage.actions_for_alert >= budget.max_actions_per_alert, "alert_action_budget"),
        (
            usage.bytes_for_alert + ARTIFACT_RESERVATION_BYTES > budget.max_bytes_per_alert,
            "alert_byte_budget",
        ),
        (
            usage.actions_in_endpoint_window >= budget.max_actions_per_endpoint_window,
            "endpoint_frequency_budget",
        ),
        (
            usage.bytes_in_endpoint_window + ARTIFACT_RESERVATION_BYTES
            > budget.max_bytes_per_endpoint_window,
            "endpoint_byte_budget",
        ),
        (
            usage.active_for_endpoint >= budget.max_active_per_endpoint,
            "endpoint_concurrency_budget",
        ),
        (usage.active_global >= MAX_ACTIVE_GLOBAL, "global_concurrency_budget"),
    )
    for exhausted, reason in checks:
        if exhausted:
            return result("skip", reason)
    # Defense in depth even if a caller constructs an invalid model without validation.
    if asset_class != "standard":
        return result("require_approval", "asset_requires_approval")
    return result(
        entry.decision,
        "policy_requires_approval"
        if entry.decision == "require_approval"
        else "policy_auto_collection",
    )


def default_policy(rule_id: str, version: int = 1) -> AutoTriagePolicy:
    """A disabled explicit matrix; enabling a rule never grants a file-path carve-out."""
    return AutoTriagePolicy(
        schema_version="1",
        rule_id=rule_id,
        version=version,
        enabled=False,
        entries=[
            ActionPolicy(
                action=action,
                asset_class=asset,
                decision="auto_dispatch"
                if asset == "standard" and action != "COLLECT_FILE"
                else "require_approval",
            )
            for asset in ("standard", "critical", "unknown")
            for action in COLLECT_ACTIONS
        ],
    )
