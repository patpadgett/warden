"""Warden — one door to your homelab."""

try:
    from ._version import __version__
except ImportError:  # pragma: no cover - generated file may be absent in editable installs
    __version__ = "0.1.0"

__all__ = ["__version__"]
