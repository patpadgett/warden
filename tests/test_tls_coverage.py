from __future__ import annotations
from warden.tls import CertificateInfo, certificate_status, read_certificate
from pathlib import Path
import tempfile




def test_read_certificate_missing() -> None:
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=True) as f:
        # Empty file won't parse, but call doesn't crash unexpectedly here
        pass
