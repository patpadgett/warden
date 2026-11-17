"""Jinja environment and presentation helpers for Warden.

The module creates a :class:`jinja2.Environment` via Starlette's ``Jinja2Templates``
and registers custom filters and globals used throughout the admin UI.
"""

from __future__ import annotations

from pathlib import Path

from starlette.templating import Jinja2Templates

from warden import __version__
from warden.utils import (
    absolute_time,
    humanize_bytes,
    iso_time,
    parse_user_agent,
    relative_time,
    route_color,
    route_initials,
    truncate,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["relative_time"] = relative_time
templates.env.filters["absolute_time"] = absolute_time
templates.env.filters["iso_time"] = iso_time
templates.env.filters["initials"] = route_initials
templates.env.filters["route_color"] = route_color
templates.env.filters["bytes"] = humanize_bytes
templates.env.filters["client"] = parse_user_agent
templates.env.filters["truncate_middle"] = truncate
templates.env.globals["static_prefix"] = "/_warden/static"
templates.env.globals["app_version"] = __version__
