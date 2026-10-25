"""ASGI entry point for ``uvicorn warden.asgi:app``."""

from __future__ import annotations

import os

from warden.main import create_app

app = create_app(os.environ.get("WARDEN_CONFIG") or None)

__all__ = ["app"]
