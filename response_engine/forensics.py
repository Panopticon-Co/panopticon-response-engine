"""Pure forensic recommendations and metadata checks, never execution or attestation.

These local domain models do not extend any command or central wire schema.
Manager remains responsible for authorization, signature/hash verification,
artifact storage, custody and execution-time endpoint identity checks.
"""

from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    model_validator,
)

from response_engine.artifacts import ArtifactManifest
from response_engine.policy import Tier, classify_tier
from response_engine.recommendation import translate_recommendation
from response_engine.triage import ApprovedFile, AssetClass, CollectAction

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"\S")]
HostIdentifier = Annotated[str, Field(min_length=1, max_length=256, pattern=r"\S")]
COLLECTION_KINDS = {
    "COLLECT_PROCESS_INFO": "process_snapshot",
    "COLLECT_NETWORK_CONNECTIONS": "network_snapshot",
    "COLLECT_FILE": "file_metadata",
}


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ProcessIdentity(_Closed):
    """Observed native identity tokens; never reconstructed from a timestamp."""

    pid: StrictInt = Field(ge=1, le=0xFFFFFFFF)
    start_time_ticks: StrictInt = Field(ge=1, le=0xFFFFFFFFFFFFFFFF)
    boot_id: str | None = Field(default=None, pattern=r"^boot_[0-9a-f]{64}$")


class EvidenceReference(_Closed):
    """Original signed-manifest metadata, not proof its signature was verified."""

    source_id: Identifier
    source_record_id: Identifier
    manifest: ArtifactManifest


class ForensicContext(_Closed):
    alert_id: Identifier
    agent_id: Identifier
    host_id: HostIdentifier
    source_id: Identifier
    source_record_id: Identifier
    observed_at: AwareDatetime
    rule_id: Identifier | None = None
    recommendation_id: Identifier | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def consistent_evidence_scope(self):
        identities = set()
        for reference in self.evidence:
            manifest = reference.manifest
            if manifest.agent_id != self.agent_id or manifest.host_id != self.host_id:
                raise ValueError("evidence reference belongs to another endpoint")
            if manifest.artifact_id in identities:
                raise ValueError("duplicate artifact identity in forensic context")
            identities.add(manifest.artifact_id)
        return self


class ForensicCollectionRequest(_Closed):
    schema_version: Literal["1"] = "1"
    request_id: Identifier
    action: CollectAction
    context: ForensicContext
    process: ProcessIdentity | None = None
    file: ApprovedFile | None = None

    @model_validator(mode="after")
    def exact_collection_target(self):
        if (self.process is not None) != (self.action == "COLLECT_PROCESS_INFO"):
            raise ValueError("only process collection requires a process identity")
        if (self.file is not None) != (self.action == "COLLECT_FILE"):
            raise ValueError("only file metadata collection requires an exact native file path")
        return self


class ForensicCollectionPolicy(_Closed):
    """Version-1 opt-in policy; may strengthen but never lower existing tiers.

    Asset classification must come from the consumer's authoritative registry,
    not an endpoint or detection recommendation. No setting authorizes execution.
    """

    schema_version: Literal["1"] = "1"
    policy_id: Identifier
    version: StrictInt = Field(ge=1, le=2147483647)
    enabled: StrictBool = False
    allowed_actions: list[CollectAction] = Field(
        default_factory=lambda: list(COLLECTION_KINDS), max_length=3
    )
    require_approval: list[CollectAction] = Field(
        default_factory=lambda: list(COLLECTION_KINDS), max_length=3
    )

    @model_validator(mode="after")
    def unique_actions(self):
        for actions in (self.allowed_actions, self.require_approval):
            if len(actions) != len(set(actions)):
                raise ValueError("duplicate forensic policy action")
        return self


class ForensicCollectionPlan(_Closed):
    """Advisory output only: no command ID, expiry, authorization or lifecycle state."""

    schema_version: Literal["1"] = "1"
    request: ForensicCollectionRequest
    policy_id: Identifier
    policy_version: StrictInt = Field(ge=1)
    asset_class: AssetClass
    decision: Literal["recommend", "require_approval", "skip"]
    reason: Literal[
        "policy_disabled", "action_not_allowed", "asset_requires_approval",
        "collection_requires_approval", "collection_recommended",
    ]
    authorization_tier: Literal["AUTO_SAFE", "ANALYST_APPROVAL"]
    evidence_kind: Literal["process_snapshot", "network_snapshot", "file_metadata"]
    command_schema_version: Literal["1", "2"]
    target: dict


def plan_forensic_collection(
    request: ForensicCollectionRequest,
    policy: ForensicCollectionPolicy,
    *,
    asset_class: AssetClass = "unknown",
) -> ForensicCollectionPlan:
    """Validate then recommend one existing collection action without I/O.

    Identical inputs produce identical outputs; there is no clock, generated
    identifier, evidence hash or dispatch side effect. Revalidate model instances
    too, so mutated nested values/model_construct cannot bypass these checks.
    """
    request = ForensicCollectionRequest.model_validate(request.model_dump())
    policy = ForensicCollectionPolicy.model_validate(policy.model_dump())
    if asset_class not in ("standard", "critical", "unknown"):
        raise ValueError("unknown asset classification")
    target = {}
    command_version = "1"
    if request.process is not None:
        identity = request.process
        mapped = translate_recommendation(
            request.action,
            {"target_pid": identity.pid, "target_start_time_ticks": identity.start_time_ticks},
        )
        if mapped is None:
            raise ValueError("process identity cannot be translated safely")
        target = mapped[1]
        if identity.boot_id is not None:
            command_version = "2"
            target = {
                "pid": identity.pid, "start_time_ticks": str(identity.start_time_ticks),
                "boot_id": identity.boot_id,
            }
    elif request.file is not None:
        target = {"path": request.file.path}

    tier = classify_tier(request.action)
    if asset_class != "standard" or request.action in policy.require_approval:
        tier = Tier.ANALYST_APPROVAL
    if not policy.enabled:
        decision, reason = "skip", "policy_disabled"
    elif request.action not in policy.allowed_actions:
        decision, reason = "skip", "action_not_allowed"
    elif asset_class != "standard":
        decision, reason = "require_approval", "asset_requires_approval"
    elif tier == Tier.ANALYST_APPROVAL:
        decision, reason = "require_approval", "collection_requires_approval"
    else:
        decision, reason = "recommend", "collection_recommended"
    return ForensicCollectionPlan(
        request=request, policy_id=policy.policy_id, policy_version=policy.version,
        asset_class=asset_class, decision=decision, reason=reason,
        authorization_tier=tier.value, evidence_kind=COLLECTION_KINDS[request.action],
        command_schema_version=command_version, target=target,
    )


class EvidenceExpectation(_Closed):
    """Trusted command/case binding supplied by Manager, not by an artifact."""

    action: CollectAction
    agent_id: Identifier
    host_id: HostIdentifier
    command_id: Identifier
    correlation_id: Identifier


def validate_evidence_metadata(
    manifest: dict | ArtifactManifest, *, expected: EvidenceExpectation,
) -> ArtifactManifest:
    """Check existing manifest shape and command scope, without claiming integrity.

    This checks SHA-256 *representation*, not content bytes, enrolled keys or
    signature authenticity. Manager must perform those checks independently.
    No evidence identifiers, timestamps, signatures or hashes are synthesized.
    """
    expected = EvidenceExpectation.model_validate(expected.model_dump())
    value = ArtifactManifest.model_validate(
        manifest.model_dump() if isinstance(manifest, ArtifactManifest) else manifest
    )
    for field in ("agent_id", "host_id", "command_id", "correlation_id"):
        if getattr(value, field) != getattr(expected, field):
            raise ValueError(f"evidence {field} does not match expected command scope")
    if value.kind != COLLECTION_KINDS[expected.action]:
        raise ValueError("evidence kind does not match collection action")
    return value
