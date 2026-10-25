"""Internationalization utilities for Warden.

Provides a simple wrapper around the standard :mod:`gettext` module to load
translation catalogs from the ``warden/locale`` directory. The default language
is English (``en``). The module exposes a global ``_`` function compatible with
Jinja2's expected translation helper.
"""

from __future__ import annotations

import gettext
from pathlib import Path

# Base directory containing the locale subfolders.
_LOCALE_DIR = Path(__file__).parent / "locale"


def get_translation(lang: str = "en"):
    """Return a :class:`gettext.NullTranslations` or real translation.

    If the specified language catalog is missing, a null translation that returns
    the original strings is returned.
    """
    try:
        return gettext.translation("messages", localedir=str(_LOCALE_DIR), languages=[lang])
    except FileNotFoundError:
        return gettext.NullTranslations()

# Load the default translation at import time.
_translation = get_translation()
_ = _translation.gettext


def set_language(lang: str) -> None:
    """Change the active language for the global ``_`` function.

    This updates the ``_`` callable used throughout the application.
    """
    global _, _translation
    _translation = get_translation(lang)
    _ = _translation.gettext
