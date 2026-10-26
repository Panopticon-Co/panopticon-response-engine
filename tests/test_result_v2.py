import pytest
from pydantic import ValidationError

from response_engine.contract import CommandResult


def test_indeterminate_requires_version_two_and_correlation():
    fields = dict(result_id="result-1", command_id="cmd-1", outcome="indeterminate")
    with pytest.raises(ValidationError):
        CommandResult(**fields)
    with pytest.raises(ValidationError):
        CommandResult(**fields, schema_version="2")
    assert (
        CommandResult(**fields, schema_version="2", correlation_id="corr-1").outcome
        == "indeterminate"
    )
