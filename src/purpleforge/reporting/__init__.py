"""Report rendering: terminal console output, HTML and JSON."""

from purpleforge.reporting.console import render_console
from purpleforge.reporting.html import render_html
from purpleforge.reporting.navigator import build_navigator_layer

__all__ = ["render_console", "render_html", "build_navigator_layer"]
