import json
import pytest
import allure
import subprocess
from pathlib import Path

from tests.utils.mpe_runner import run_mpe_decision
from tests.utils.allure_helpers import attach_payload, attach_bundle_yaml, attach_output

BASE_DIR = Path(__file__).resolve().parents[3]

# Paths
JSON_PAYLOAD_DIR = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "porc_json"
YAML_BUNDLE_FILE = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "yml" / "broken_alpha.yml"

# Expected error messages from broken_alpha.yml
EXPECTED_ERRORS = [
    "validation failed",
    "undefined references",
    "not found",
    "cycle"
]

# JSON files to test with the broken YAML
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
@allure.tag("iam", "Policy Engine", "Broken YAML", "Cycle Detection", "broken_alpha")
def test_broken_alpha_fails_with_expected_errors(filename):
    payload = load_payload(filename)

    if not YAML_BUNDLE_FILE.exists():
        pytest.fail(f"YAML bundle not found: {YAML_BUNDLE_FILE}")

    # Attach artifacts for debugging
    attach_payload(payload)
    attach_bundle_yaml(YAML_BUNDLE_FILE)

    try:
        result = run_mpe_decision(payload, YAML_BUNDLE_FILE, allow_error=False)
        # If it succeeded, that's a failure in this test context
        pytest.fail("Expected MPE to fail due to broken YAML, but it succeeded.")
    except subprocess.CalledProcessError as e:
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        combined_output = stdout + "\n" + stderr
        attach_output(combined_output or "No output captured from mpe command.")

        for expected_error in EXPECTED_ERRORS:
            assert expected_error.lower() in combined_output.lower(), \
                f"Expected error '{expected_error}' not found in MPE output"
