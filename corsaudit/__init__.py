"""CORSAUDIT - Detect permissive/misconfigured CORS from response headers or a config.

Defensive / authorized-testing analysis tool. It performs NO requests and NO
attacks: it only analyzes header sets you have already captured (or a JSON/INI
config) and reports likely CORS misconfigurations such as the classic
wildcard-origin + credentials combination.
"""
from .core import (
    Finding,
    analyze_headers,
    analyze_config,
    parse_header_block,
    SEVERITY_ORDER,
)

TOOL_NAME = "corsaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "analyze_headers",
    "analyze_config",
    "parse_header_block",
    "SEVERITY_ORDER",
]
