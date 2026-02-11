"""
Sample tests for PolicyEngine - demonstrating test patterns.
"""

import subprocess
from pathlib import Path

import pytest


class TestPolicyEngineCLI:
    """Test suite for MPE CLI commands."""

    def test_mpe_binary_exists(self, mpe_binary: Path):
        """Test that the mpe binary is available."""
        assert mpe_binary.exists()
        assert mpe_binary.is_file()

    def test_mpe_version(self, mpe_binary: Path):
        """Test that mpe version works."""
        result = subprocess.run(
            [str(mpe_binary), "version"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0, "Version output should not be empty"

    @pytest.mark.policy
    def test_lint_sample_policy(self, mpe_binary: Path, sample_policy_domain: Path):
        """Test linting a sample PolicyDomain."""
        result = subprocess.run(
            [str(mpe_binary), "lint", "-f", str(sample_policy_domain)],
            capture_output=True,
            text=True
        )
        # Lint should pass or at least not crash
        assert result.returncode in [0, 1]  # 0 = pass, 1 = warnings

    def test_mpe_help_command(self, mpe_binary: Path):
        """Test that mpe --help displays usage information."""
        result = subprocess.run(
            [str(mpe_binary), "--help"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "mpe" in result.stdout.lower()
        assert "COMMANDS" in result.stdout or "commands" in result.stdout
        # Should show main commands
        assert "test" in result.stdout
        assert "serve" in result.stdout
        assert "lint" in result.stdout


@pytest.mark.unit
class TestProjectStructure:
    """Basic tests for project structure."""

    def test_project_root_exists(self, project_root: Path):
        """Test that project root is valid."""
        assert project_root.exists()
        assert project_root.is_dir()

    def test_testdata_exists(self, testdata_dir: Path):
        """Test that testdata directory exists."""
        assert testdata_dir.exists()
        assert testdata_dir.is_dir()

    def test_sample_policy_domain_exists(self, sample_policy_domain: Path):
        """Test that sample PolicyDomain file exists."""
        assert sample_policy_domain.exists()
        assert sample_policy_domain.suffix in [".yaml", ".yml"]

    def test_policy_domain_structure(self, sample_policy_domain: Path):
        """Test that PolicyDomain file has valid YAML structure."""
        import yaml

        with open(sample_policy_domain, 'r') as f:
            config = yaml.safe_load(f)

        # Verify it's a valid YAML
        assert config is not None
        assert isinstance(config, dict)

        # Should have either PolicyDomain structure or mock config structure
        is_policy_domain = "apiVersion" in config and "kind" in config
        is_mock_config = "mock" in config or "include" in config

        assert is_policy_domain or is_mock_config, "File should be either a PolicyDomain or mock config"


@pytest.mark.integration
@pytest.mark.skip(reason="Requires running MPE server - enable when ready")
class TestPolicyEngineAPI:
    """Integration tests for PolicyEngine HTTP API."""

    def test_health_endpoint(self, mpe_server: str):
        """Test the health check endpoint."""
        import requests

        response = requests.get(f"{mpe_server}/health")
        assert response.status_code == 200

    def test_authorization_decision(
        self,
        mpe_server: str,
        sample_principal: dict,
        sample_resource: dict
    ):
        """Test making an authorization decision."""
        import requests

        decision_request = {
            "principal": sample_principal,
            "action": "read",
            "resource": sample_resource,
        }

        response = requests.post(
            f"{mpe_server}/v1/authorize",
            json=decision_request
        )

        assert response.status_code == 200
        data = response.json()
        assert "allow" in data
        assert isinstance(data["allow"], bool)


@pytest.mark.smoke
class TestQuickSmoke:
    """Quick smoke tests that should always pass."""

    def test_imports(self):
        """Test that required libraries can be imported."""
        import pytest
        import yaml
        assert pytest is not None
        assert yaml is not None

    def test_fixtures_available(
        self,
        project_root: Path,
        sample_principal: dict,
        sample_resource: dict
    ):
        """Test that common fixtures are available."""
        assert project_root.exists()
        assert sample_principal["id"] == "user-123"
        assert sample_resource["type"] == "document"
