import json
import pytest
import allure
import subprocess
from pathlib import Path

from tests.utils.mpe_runner import run_mpe_decision
from tests.utils.allure_helpers import attach_payload, attach_bundle_yaml, attach_output

BASE_DIR = Path(__file__).resolve().parents[3]

# === File locations ===
JSON_PAYLOAD_DIR = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "porc_json"
YAML_BUNDLE_FILE = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "yml" / "invalid_policy_reference.yml"

# === Expected error messages ===
EXPECTED_ERRORS = [
    "missing-lib",
    "not found in domain",
     "invalid-policy",
    "library reference",

]

# === JSON files to test ===
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

def load_payload(filename):
    filepath = JSON_PAYLOAD_DIR / filename
    if not filepath.exists():
        pytest.fail(f"JSON payload file not found: {filepath}")
    with open(filepath, "r") as f:
        return json.load(f)

@pytest.mark.parametrize("filename", json_test_files, ids=[f.replace(".json", "") for f in json_test_files])
@allure.tag("iam", "Policy Engine", "Broken YAML", "Invalid Policy Reference", "invalid_policy_reference")
def test_invalid_policy_reference_fails_with_expected_errors(filename):
    payload = load_payload(filename)

    if not YAML_BUNDLE_FILE.exists():
        pytest.fail(f"YAML bundle not found: {YAML_BUNDLE_FILE}")

    # Allure attachments
    attach_payload(payload)
    attach_bundle_yaml(YAML_BUNDLE_FILE)

    try:
        result = run_mpe_decision(payload, YAML_BUNDLE_FILE, allow_error=False)
        pytest.fail("Expected MPE to fail due to invalid policy reference, but it succeeded.")
    except subprocess.CalledProcessError as e:
        combined_output = (e.stdout or "") + "\n" + (e.stderr or "")
        attach_output(combined_output or "No output captured from mpe command.")

        for expected_error in EXPECTED_ERRORS:
            assert expected_error.lower() in combined_output.lower(), \
                f"Expected error '{expected_error}' not found in MPE output"
