"""Closed signed JSON-artifact manifest and domain-separated signing bytes.

No key custody, networking, file access or new endpoint action belongs here.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class ArtifactAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    algorithm: Literal["ES256"]
    key_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$", min_length=88, max_length=88)


class ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["2"]
    artifact_id: str = Field(pattern=r"^art_[0-9a-f]{64}$")
    agent_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=256)
    command_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    kind: Literal["process_snapshot", "network_snapshot", "file_metadata", "execution_report"]
    media_type: Literal["application/json"]
    content_bytes: StrictInt = Field(ge=1, le=1048576)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    produced_at_unix: StrictInt = Field(ge=0, le=253402300799)
    authorization: ArtifactAuthorization


FIELDS = (
    "schema_version",
    "artifact_id",
    "agent_id",
    "host_id",
    "command_id",
    "correlation_id",
    "kind",
    "media_type",
    "content_bytes",
    "sha256",
    "produced_at_unix",
    "algorithm",
    "key_id",
)


def artifact_signing_input(value: dict) -> bytes:
    manifest = ArtifactManifest.model_validate(value).model_dump()
    fields = {**manifest, **manifest["authorization"]}
    output = bytearray(b"panopticon-response-artifact-auth/2\n")
    for name in FIELDS:
        data = str(fields[name]).encode("utf-8")
        output.extend(name.encode() + b":" + str(len(data)).encode() + b":" + data + b"\n")
    return bytes(output)
