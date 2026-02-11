import json
import os
import pytest
import allure
import subprocess
from pathlib import Path

from tests.utils.mpe_runner import run_mpe_decision
from tests.utils.allure_helpers import attach_payload, attach_bundle_yaml

BASE_DIR = Path(__file__).resolve().parents[3]

JSON_PAYLOAD_DIR = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "porc_json"
YAML_BUNDLE_FILE = BASE_DIR / "tests" / "test_data" / "api" / "payloads" / "yml" / "bad_rego.yml"

EXPECTED_ERRORS = [
    "rego compilation failed",
    "package expected",
    "var cannot be used for rule name"
]

def load_payload(filename):
    filepath = JSON_PAYLOAD_DIR / filename
    if not filepath.exists():
        pytest.fail(f"JSON payload file not found: {filepath}")
    with open(filepath, "r") as f:
        return json.load(f)

# 🚨 BAD REGO TEST: Parametrized with different JSON payloads
bad_rego_test_cases = [
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

@pytest.mark.parametrize("filename", bad_rego_test_cases, ids=[os.path.splitext(f)[0] for f in bad_rego_test_cases])
def test_bad_rego_yml_fails_with_expected_errors(filename):
    payload = load_payload(filename)

    if not YAML_BUNDLE_FILE.exists():
        pytest.fail(f"YAML bundle file not found: {YAML_BUNDLE_FILE}")

    # Attach payload and YAML to Allure
    attach_payload(payload)
    attach_bundle_yaml(YAML_BUNDLE_FILE)

    try:
        run_mpe_decision(payload, YAML_BUNDLE_FILE, allow_error=False)
        pytest.fail("Expected policy compilation to fail, but it succeeded.")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr
        # Attach stderr to Allure
        allure.attach(stderr, name="MPE Compilation Error", attachment_type=allure.attachment_type.TEXT)

        for expected_error in EXPECTED_ERRORS:
            assert expected_error in stderr, f"Missing expected error: '{expected_error}'"
