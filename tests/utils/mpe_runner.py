import json
import subprocess
from pathlib import Path

import allure
import pytest


def _resolve_mpe_binary():
    project_root = Path(__file__).resolve().parents[1]
    local_binary = project_root / "target" / "mpe"

    if local_binary.exists():
        return str(local_binary)

    return "mpe"


def run_mpe_decision(payload, bundle_path, allow_error=False):
    result = subprocess.run(
        [_resolve_mpe_binary(), "test", "decision", "--bundle", str(bundle_path)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=not allow_error,
    )
    return result


def normalize_decision(value):
    if value is None:
        return ""
    normalized = str(value).strip().upper()
    aliases = {
        "ALLOW": "GRANT",
        "PERMIT": "GRANT",
        "DENY": "DENY",
        "REJECT": "DENY",
    }
    return aliases.get(normalized, normalized)


def handle_mpe_failure(result):
    allure.attach(
        result.stdout or "",
        name="stdout",
        attachment_type=allure.attachment_type.JSON,
    )
    allure.attach(
        result.stderr or "",
        name="stderr",
        attachment_type=allure.attachment_type.JSON,
    )
    pytest.fail(f"`mpe` command failed:\n{result.stderr}")

