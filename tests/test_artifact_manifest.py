import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from response_engine.artifacts import ArtifactManifest, artifact_signing_input

ROOT = Path(__file__).resolve().parent / "vendor/panopticon-contracts"


def vector():
    return json.loads((ROOT / "fixtures/artifacts/signing-v2.json").read_text())


def test_signing_input_matches_central_manifest_vector():
    fixture = vector()
    assert artifact_signing_input(fixture["manifest"]) == base64.b64decode(
        fixture["signing_input_base64"]
    )
    data = base64.b64decode(fixture["content_base64"])
    assert len(data) == fixture["manifest"]["content_bytes"]
    assert hashlib.sha256(data).hexdigest() == fixture["manifest"]["sha256"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("content_bytes", True),
        ("content_bytes", 1048577),
        ("produced_at_unix", "1"),
        ("schema_version", "1"),
        ("kind", "raw_file"),
        ("content_base64", "e30="),
        ("authorization", {}),
    ],
)
def test_closed_manifest_refuses_ambiguous_or_unsigned_evidence(field, value):
    manifest = copy.deepcopy(vector()["manifest"])
    manifest[field] = value
    with pytest.raises(ValidationError):
        ArtifactManifest.model_validate(manifest)
