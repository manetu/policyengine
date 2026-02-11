import json
import os
import pytest
import allure
from pathlib import Path

from tests.utils.mpe_runner import run_mpe_decision, handle_mpe_failure, normalize_decision
from tests.utils.allure_helpers import attach_payload, attach_bundle_yaml, attach_output

BASE_DIR = Path(__file__).resolve().parents[3]

JSON_PAYLOAD_DIR = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "porc_json"
YAML_BUNDLE_FILE = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "yml" / "consolidated.yml"

def load_payload(filename):
    filepath = JSON_PAYLOAD_DIR / filename
    if not filepath.exists():
        pytest.fail(f"JSON payload file not found: {filepath}")
    with open(filepath, "r") as f:
        return json.load(f)

def run_and_validate_policy_test(filename, expected_allow: bool):
    payload = load_payload(filename)

    if not YAML_BUNDLE_FILE.exists():
        pytest.fail(f"Bundle YAML file not found: {YAML_BUNDLE_FILE}")

    result = run_mpe_decision(payload, YAML_BUNDLE_FILE, allow_error=False)

    attach_payload(payload)
    attach_bundle_yaml(YAML_BUNDLE_FILE)
    attach_output(result.stdout)

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail("Output is not valid JSON")

    decision = normalize_decision(response.get("decision"))
    references = response.get("references", [])

    deny_refs = [r for r in references if normalize_decision(r.get("decision")) == "DENY"]
    if expected_allow and deny_refs:
        allure.attach(json.dumps(deny_refs, indent=2), name="Denied References", attachment_type=allure.attachment_type.JSON)
        pytest.fail("Expected allow, but deny references found")

    if expected_allow:
        assert decision == "GRANT", f"Expected allow (GRANT), got: {decision}"
    else:
        assert decision != "GRANT", f"Expected deny, but got allow"

test_cases = [
    ("valid_admin.json", True),
    ("admin_with_write_api_scope.json", False),
    ("access_denied_when_role_is_null.json", False),
    ("access_allowed_when_scope_is_null.json", True),
    ("valid_admin_with_multiple_scopes_allows_access.json", True),
    ("non_admin_with_read_scope_is_denied_access.json", False),
    ("access_denied_with_invalid_scope_format.json", False),
    ("access_denied_with_additional_but_irrelevant_scopes.json", False),
    ("access_denied_for_unauthorized_http_method_operation.json", False),
    ("access_allowed_for_authorized_http_method_operation.json", True)
]

@pytest.mark.parametrize(
    "filename,expected_allow",
    test_cases,
    ids=[os.path.splitext(name)[0] for name, _ in test_cases]
)
def test_policy_decision(filename, expected_allow):
    run_and_validate_policy_test(filename, expected_allow)