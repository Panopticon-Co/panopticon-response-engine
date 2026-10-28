import json
from pathlib import Path

import pytest

from response_engine.signing import UnsignableCommand, signing_input

ROOT = Path(__file__).parent / "vendor/panopticon-contracts"
VECTORS = json.loads((ROOT / "fixtures/commands/signing-vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_canonical_signing_bytes_match_retained_native_vectors(vector):
    assert signing_input(vector["command"]) == vector["signing_input"].encode("utf-8")


def test_signing_refuses_schema_disagreement_and_extra_execution_fields():
    command = VECTORS["vectors"][0]["command"]
    with pytest.raises(UnsignableCommand):
        signing_input({**command, "schema_version": "2"})
    with pytest.raises(UnsignableCommand):
        signing_input({**command, "shell": "echo unsafe"})
