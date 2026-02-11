"""
Pytest configuration and shared fixtures for PolicyEngine tests.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Generator

import pytest


# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def testdata_dir(project_root: Path) -> Path:
    """Return the testdata directory path."""
    return project_root / "testdata"


@pytest.fixture(scope="session")
def mpe_binary(project_root: Path) -> Path:
    """
    Ensure the mpe binary is built and return its path.

    This fixture builds the PolicyEngine CLI if it doesn't exist.
    """
    binary_path = project_root / "target" / "mpe"

    if not binary_path.exists():
        print("\n🔨 Building mpe binary...")
        subprocess.run(
            ["make", "build"],
            cwd=project_root,
            check=True,
            capture_output=True
        )

    assert binary_path.exists(), "Failed to build mpe binary"
    return binary_path


@pytest.fixture
def sample_policy_domain(testdata_dir: Path) -> Path:
    """Return path to a sample PolicyDomain YAML file."""
    policy_file = testdata_dir / "mpe-config.yaml"
    assert policy_file.exists(), f"Sample policy not found: {policy_file}"
    return policy_file


@pytest.fixture(scope="session")
def mpe_server_port() -> int:
    """Return the port for the MPE server during tests."""
    return int(os.getenv("MPE_TEST_PORT", "9090"))


@pytest.fixture(scope="function")
def mpe_server(
    mpe_binary: Path,
    sample_policy_domain: Path,
    mpe_server_port: int
) -> Generator[str, None, None]:
    """
    Start a PolicyEngine server for integration tests.

    Yields:
        Base URL of the running server (e.g., "http://localhost:9090")
    """
    server_url = f"http://localhost:{mpe_server_port}"

    # Start the server
    print(f"\n🚀 Starting MPE server on {server_url}...")
    process = subprocess.Popen(
        [
            str(mpe_binary),
            "serve",
            "--bundle", str(sample_policy_domain),
            "--http-port", str(mpe_server_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT
    )

    # Wait for server to be ready
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            import requests
            response = requests.get(f"{server_url}/health", timeout=1)
            if response.status_code == 200:
                print(f"✅ MPE server ready after {attempt + 1} attempts")
                break
        except Exception:
            time.sleep(0.5)
    else:
        process.kill()
        raise RuntimeError("MPE server failed to start within timeout")

    yield server_url

    # Cleanup
    print("\n🛑 Stopping MPE server...")
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.fixture
def sample_principal() -> dict:
    """Return a sample principal for testing authorization."""
    return {
        "id": "user-123",
        "email": "test@example.com",
        "roles": ["admin"],
        "attributes": {
            "department": "engineering",
            "clearance": "high"
        }
    }


@pytest.fixture
def sample_resource() -> dict:
    """Return a sample resource for testing authorization."""
    return {
        "id": "resource-456",
        "type": "document",
        "owner": "user-123",
        "classification": "confidential"
    }
