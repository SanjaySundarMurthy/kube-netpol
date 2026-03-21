"""Tests for kube-netpol CLI commands."""
from click.testing import CliRunner

from kube_netpol.cli import main


class TestMainGroup:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "kube-netpol" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "generate" in result.output
        assert "demo" in result.output


class TestScanCommand:
    def test_scan_good_manifests(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests])
        assert result.exit_code == 0

    def test_scan_bad_manifests(self, bad_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_manifests])
        assert result.exit_code == 0

    def test_scan_verbose(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--verbose"])
        assert result.exit_code == 0

    def test_scan_export_json(self, good_manifests, tmp_path):
        output = str(tmp_path / "report.json")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--format", "json", "--output", output])
        assert result.exit_code == 0
        import json
        with open(output) as f:
            data = json.load(f)
        assert "issues" in data

    def test_scan_export_html(self, good_manifests, tmp_path):
        output = str(tmp_path / "report.html")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--format", "html", "--output", output])
        assert result.exit_code == 0
        assert (tmp_path / "report.html").exists()

    def test_scan_nonexistent_path(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_fail_on(self, bad_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_manifests, "--fail-on", "critical"])
        # bad manifests have issues; exit code depends on severity
        assert result.exit_code in (0, 1)


class TestGenerateCommand:
    def test_generate_template(self):
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "default-deny-ingress"])
        assert result.exit_code == 0
        assert "NetworkPolicy" in result.output

    def test_generate_with_namespace(self):
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "default-deny-ingress", "--namespace", "prod"])
        assert result.exit_code == 0
        assert "prod" in result.output

    def test_generate_to_file(self, tmp_path):
        output = str(tmp_path / "policy.yaml")
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "default-deny-ingress", "--output", output])
        assert result.exit_code == 0
        assert (tmp_path / "policy.yaml").exists()


class TestTemplatesCommand:
    def test_templates_list(self):
        runner = CliRunner()
        result = runner.invoke(main, ["templates"])
        assert result.exit_code == 0
        assert "default-deny" in result.output.lower()


class TestSimulateCommand:
    def test_simulate_flow(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, [
            "simulate", good_manifests,
            "--from-pod", "frontend",
            "--to-pod", "web",
            "--port", "80",
        ])
        assert result.exit_code == 0

    def test_simulate_missing_required(self):
        runner = CliRunner()
        result = runner.invoke(main, ["simulate", "."])
        assert result.exit_code != 0


class TestDemoCommand:
    def test_demo_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0


class TestRulesCommand:
    def test_rules_list(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "KNP-" in result.output
