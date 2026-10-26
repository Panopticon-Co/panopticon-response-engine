"""The Python CommandResult and the published command-result-v2 JSON Schema must
agree on every golden execution fixture: both accept the valid ones and both
refuse the invalid ones. Disagreement means one side of the contract drifted."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from response_engine.contract import CommandResult

jsonschema = pytest.importorskip("jsonschema")

CONTRACTS = Path(__file__).resolve().parent / "vendor" / "panopticon-contracts"
SCHEMA = CONTRACTS / "schema" / "command-result-v2.schema.json"
FIXTURES = CONTRACTS / "fixtures" / "results" / "execution-v2.json"

pytestmark = pytest.mark.skipif(
    not SCHEMA.is_file(), reason="vendored contracts lack command-result-v2"
)


def _cases(group):
    return json.loads(FIXTURES.read_text(encoding="utf-8"))[group] if FIXTURES.is_file() else []


def _schema_accepts(record) -> bool:
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))
    return not list(validator.iter_errors(record))


def _model_accepts(record) -> bool:
    try:
        CommandResult.model_validate(record)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize("record", _cases("valid"), ids=lambda r: r.get("result_id", "?"))
def test_valid_results_accepted_by_schema_and_model(record):
    assert _schema_accepts(record) and _model_accepts(record)


@pytest.mark.parametrize("record", _cases("invalid"), ids=lambda r: r.get("result_id", "?"))
def test_invalid_results_refused_by_schema_and_model(record):
    assert not _schema_accepts(record) and not _model_accepts(record)
