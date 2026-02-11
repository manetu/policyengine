import json
import pytest
import allure
import subprocess
from pathlib import Path

from tests.utils.mpe_runner import run_mpe_decision, normalize_decision
from tests.utils.allure_helpers import attach_payload, attach_bundle_yaml, attach_output

BASE_DIR = Path(__file__).resolve().parents[3]

# Paths to test data
JSON_PAYLOAD_DIR = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "porc_json"
YAML_BUNDLE_FILE = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "yml" / "valid_alpha.yml"

# List of JSON test files
json_test_files = [
    "valid_admin.json",
    "admin_with_write_api_scope.json",
    "access_denied_when_role_is_null.json",
    "access_allowed_when_scope_is_null.json",
    "valid_admin_with_multiple_scopes_allows_access.json",
    "non_admin_with_read_scope_is_denied_access.json",
    "access_denied_with_invalid_scope_format.json",
    "access_denied_with_additional_but_irrelevant_scopes.json",
    "access_denied_for_unauthorized_http_method_operation.json",
    "access_allowed_for_authorized_http_method_operation.json"
]

# Expected error output strings
EXPECTED_ERRORS = [
    "unexpected phase1 result: true",
    "bundle not found"
]

def load_payload(filename):
    filepath = JSON_PAYLOAD_DIR / filename
    if not filepath.exists():
        pytest.fail(f"JSON payload file not found: {filepath}")
    with open(filepath, "r") as f:
        return json.load(f)

@pytest.mark.parametrize("filename", json_test_files, ids=[f.replace(".json", "") for f in json_test_files])
@allure.tag("iam", "Valid Alpha", "Unexpected Rego Result", "Bundle Not Found")
def test_valid_alpha_with_multiple_payloads(filename):
    payload = load_payload(filename)

    if not YAML_BUNDLE_FILE.exists():
        pytest.fail(f"YAML bundle not found: {YAML_BUNDLE_FILE}")

    attach_payload(payload)
    attach_bundle_yaml(YAML_BUNDLE_FILE)

    try:
        result = run_mpe_decision(payload, YAML_BUNDLE_FILE, allow_error=False)
        output = result.stdout
        attach_output(output)

        try:
            response = json.loads(output)
            decision = normalize_decision(response.get("decision"))
            assert decision == 'DENY', f"Expected decision=DENY (deny), got: {decision}"
         
        except json.JSONDecodeError:
            pytest.fail("MPE output is not valid JSON")

    except subprocess.CalledProcessError as e:
        combined_output = (e.stdout or "") + "\n" + (e.stderr or "")
        attach_output(combined_output or "No output captured from mpe command.")
        for expected_error in EXPECTED_ERRORS:
            assert expected_error.lower() in combined_output.lower(), f"Expected error '{expected_error}' not found in output"
