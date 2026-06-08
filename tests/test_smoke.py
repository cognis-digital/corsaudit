"""Smoke tests for CORSAUDIT. No network access."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from corsaudit import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze_config,
    analyze_headers,
    parse_header_block,
)
from corsaudit.cli import main  # noqa: E402


class TestParse(unittest.TestCase):
    def test_parse_header_block(self):
        text = "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nVary: Origin\n\ngarbage"
        h = parse_header_block(text)
        self.assertEqual(h["access-control-allow-origin"], ["*"])
        self.assertIn("vary", h)
        self.assertNotIn("garbage", h)


class TestAnalyzeHeaders(unittest.TestCase):
    def test_wildcard_with_credentials_is_critical(self):
        findings = analyze_headers(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        rules = {f.rule for f in findings}
        self.assertIn("CORS001", rules)
        self.assertEqual(findings[0].severity, "critical")

    def test_wildcard_no_credentials_is_low(self):
        findings = analyze_headers({"Access-Control-Allow-Origin": "*"})
        self.assertEqual([f.rule for f in findings], ["CORS003"])
        self.assertEqual(findings[0].severity, "low")

    def test_origin_reflection_with_credentials(self):
        findings = analyze_headers(
            {
                "Access-Control-Allow-Origin": "https://attacker.example",
                "Access-Control-Allow-Credentials": "true",
            },
            request_origin="https://attacker.example",
        )
        self.assertIn("CORS002", {f.rule for f in findings})

    def test_null_origin(self):
        findings = analyze_headers({"Access-Control-Allow-Origin": "null"})
        self.assertIn("CORS004", {f.rule for f in findings})

    def test_clean_config_no_findings(self):
        findings = analyze_headers(
            {"Access-Control-Allow-Origin": "https://app.example"},
            request_origin="https://other.example",
        )
        self.assertEqual(findings, [])

    def test_multiple_acao_values(self):
        findings = analyze_headers(
            {"Access-Control-Allow-Origin": ["*", "https://a.example"]}
        )
        self.assertIn("CORS009", {f.rule for f in findings})


class TestAnalyzeConfig(unittest.TestCase):
    def test_config_wildcard_credentials(self):
        findings = analyze_config(
            {"allowed_origins": ["*"], "allow_credentials": True}
        )
        self.assertIn("CORS001", {f.rule for f in findings})

    def test_config_http_origin(self):
        findings = analyze_config({"origins": "http://insecure.example"})
        self.assertIn("CORS007", {f.rule for f in findings})

    def test_config_clean(self):
        findings = analyze_config(
            {"allowed_origins": ["https://app.example"], "allow_credentials": True,
             "allowed_methods": ["GET", "POST"]}
        )
        self.assertEqual(findings, [])


class TestCli(unittest.TestCase):
    def _run(self, argv, stdin_text=None):
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        sys.stdout = io.StringIO()
        try:
            code = main(argv)
            out = sys.stdout.getvalue()
        finally:
            sys.stdin = old_stdin
            sys.stdout = old_stdout
        return code, out

    def test_headers_json_exit_1_on_finding(self):
        stdin = "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n"
        code, out = self._run(["--format", "json", "headers", "-"], stdin_text=stdin)
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], TOOL_NAME)
        self.assertEqual(payload["version"], TOOL_VERSION)
        self.assertEqual(payload["max_severity"], "critical")
        self.assertGreaterEqual(payload["finding_count"], 1)

    def test_headers_clean_exit_0(self):
        stdin = "Access-Control-Allow-Origin: https://app.example\n"
        code, out = self._run(
            ["--format", "json", "headers", "-"], stdin_text=stdin
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["finding_count"], 0)

    def test_config_subcommand(self):
        stdin = json.dumps({"allowed_origins": ["*"], "allow_credentials": True})
        code, out = self._run(["--format", "json", "config", "-"], stdin_text=stdin)
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertIn("CORS001", {f["rule"] for f in payload["findings"]})

    def test_demo_file(self):
        demo = os.path.join(
            os.path.dirname(__file__), "..", "demos", "01-basic", "response_headers.txt"
        )
        code, out = self._run(
            ["--format", "json", "headers", demo, "--origin", "https://attacker.example"]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertIn("CORS002", {f["rule"] for f in payload["findings"]})

    def test_bad_json_config_exit_2(self):
        code, _ = self._run(["config", "-"], stdin_text="{not json")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
