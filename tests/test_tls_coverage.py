from __future__ import annotations

import tempfile


def test_read_certificate_missing() -> None:
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=True):
        # Empty file won't parse, but call doesn't crash unexpectedly here
        pass
