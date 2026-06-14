"""Hardening tests — edge cases and error paths added during production hardening.

All tests are read-only; no network access.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from corsaudit.core import analyze_config, analyze_headers, parse_header_block  # noqa: E402
from corsaudit.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# Helper shared by CLI tests
# ---------------------------------------------------------------------------

def _run_cli(argv, stdin_text=None):
    """Run cli.main() with captured stdout; return (exit_code, stdout_text)."""
    old_stdin = sys.stdin
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        code = main(argv)
        out = sys.stdout.getvalue()
        err = sys.stderr.getvalue()
    finally:
        sys.stdin = old_stdin
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    return code, out, err


# ---------------------------------------------------------------------------
# core.analyze_headers — bad argument types
# ---------------------------------------------------------------------------

class TestAnalyzeHeadersValidation(unittest.TestCase):
    def test_none_headers_raises_type_error(self):
        with self.assertRaises(TypeError):
            analyze_headers(None)

    def test_non_dict_headers_raises_type_error(self):
        with self.assertRaises(TypeError):
            analyze_headers(["Access-Control-Allow-Origin: *"])

    def test_empty_headers_dict_returns_no_findings(self):
        findings = analyze_headers({})
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# core.analyze_config — bad argument types
# ---------------------------------------------------------------------------

class TestAnalyzeConfigValidation(unittest.TestCase):
    def test_none_config_raises_type_error(self):
        with self.assertRaises(TypeError):
            analyze_config(None)

    def test_list_config_raises_type_error(self):
        with self.assertRaises(TypeError):
            analyze_config(["allowed_origins", "*"])

    def test_empty_config_returns_no_findings(self):
        findings = analyze_config({})
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# parse_header_block — edge cases
# ---------------------------------------------------------------------------

class TestParseHeaderBlockEdgeCases(unittest.TestCase):
    def test_empty_string_returns_empty_dict(self):
        self.assertEqual(parse_header_block(""), {})

    def test_whitespace_only_returns_empty_dict(self):
        self.assertEqual(parse_header_block("   \n\n   "), {})

    def test_lines_without_colon_are_skipped(self):
        h = parse_header_block("HTTP/1.1 200 OK\nno-colon-here\nX-Foo: bar")
        self.assertNotIn("no-colon-here", h)
        self.assertIn("x-foo", h)

    def test_value_may_contain_colons(self):
        h = parse_header_block("Location: https://example.com:8080/path")
        self.assertEqual(h["location"], ["https://example.com:8080/path"])

    def test_duplicate_header_names_accumulate(self):
        h = parse_header_block(
            "Access-Control-Allow-Origin: https://a.example\n"
            "Access-Control-Allow-Origin: https://b.example\n"
        )
        self.assertEqual(len(h["access-control-allow-origin"]), 2)


# ---------------------------------------------------------------------------
# CLI — missing file -> exit 2
# ---------------------------------------------------------------------------

class TestCliMissingFile(unittest.TestCase):
    def test_missing_header_file_exit_2(self):
        code, _, err = _run_cli(["headers", "/nonexistent/path/file.txt"])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_missing_config_file_exit_2(self):
        code, _, err = _run_cli(["config", "/nonexistent/path/config.json"])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())


# ---------------------------------------------------------------------------
# CLI — empty input -> exit 2
# ---------------------------------------------------------------------------

class TestCliEmptyInput(unittest.TestCase):
    def test_empty_headers_stdin_exit_2(self):
        code, _, err = _run_cli(["headers", "-"], stdin_text="")
        self.assertEqual(code, 2)
        self.assertIn("empty", err.lower())

    def test_whitespace_only_headers_stdin_exit_2(self):
        code, _, err = _run_cli(["headers", "-"], stdin_text="   \n\n")
        self.assertEqual(code, 2)

    def test_empty_config_stdin_exit_2(self):
        code, _, err = _run_cli(["config", "-"], stdin_text="")
        self.assertEqual(code, 2)
        self.assertIn("empty", err.lower())


# ---------------------------------------------------------------------------
# CLI — config is not a JSON object (array/scalar) -> exit 2
# ---------------------------------------------------------------------------

class TestCliConfigNotObject(unittest.TestCase):
    def test_json_array_config_exit_2(self):
        code, _, err = _run_cli(["config", "-"], stdin_text='["allowed_origins", "*"]')
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_json_scalar_config_exit_2(self):
        code, _, err = _run_cli(["config", "-"], stdin_text='"just a string"')
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())


# ---------------------------------------------------------------------------
# CLI — binary / non-UTF-8 file
# ---------------------------------------------------------------------------

class TestCliNonUtf8File(unittest.TestCase):
    def test_binary_header_file_exit_2(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"\xff\xfe binary garbage \x00\x01")
            name = f.name
        try:
            code, _, err = _run_cli(["headers", name])
            self.assertEqual(code, 2)
            self.assertIn("error", err.lower())
        finally:
            os.unlink(name)


if __name__ == "__main__":
    unittest.main()
