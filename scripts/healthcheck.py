#!/usr/bin/env python3
"""Container health probe that works with TLS enabled or disabled."""

from __future__ import annotations

import os
import ssl
import sys
import urllib.error
import urllib.request


def status(url: str, context: ssl.SSLContext | None = None) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=3, context=context) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:
        return None


def main() -> int:
    http_url = os.environ.get(
        "WARDEN_HEALTH_URL", "http://127.0.0.1:8080/_warden/health"
    )
    if status(http_url) == 200:
        return 0

    # With TLS enabled the plain-HTTP listener only redirects. Verify the app
    # through the TLS listener instead; the certificate is irrelevant here.
    https_url = os.environ.get(
        "WARDEN_HEALTH_URL_TLS", "https://127.0.0.1:8443/_warden/health"
    )
    if status(https_url, ssl._create_unverified_context()) == 200:
        return 0

    print(f"warden health check failed: {http_url} and {https_url}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
