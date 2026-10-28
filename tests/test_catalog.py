from response_engine.catalog import action_catalog
from response_engine.contract import ACTIONS
from response_engine.policy import Tier


def test_catalog_matches_closed_contract_and_safety_policy():
    catalog = action_catalog()
    assert tuple(item.action for item in catalog) == ACTIONS
    assert all(item.tier == Tier.ANALYST_APPROVAL for item in catalog if item.disruptive)
    assert {item.target_kind for item in catalog} == {"process", "file", "host"}
