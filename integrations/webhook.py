#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Destination URL (must start with http:// or https://)")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print(
            "error: --url must start with http:// or https://: {!r}".format(args.url),
            file=sys.stderr,
        )
        return 2

    try:
        payload = sys.stdin.read().encode("utf-8")
    except UnicodeDecodeError as exc:
        print("error: stdin contains non-UTF-8 data: {}".format(exc), file=sys.stderr)
        return 2

    if not payload.strip():
        print("error: empty payload — nothing to post", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print("error: malformed --header value (missing key): {!r}".format(h), file=sys.stderr)
            return 2
        req.add_header(k.strip(), v.strip())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print("posted {} bytes -> {}".format(len(payload), r.status))
        return 0
    except Exception as e:
        print("webhook error: {}".format(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
