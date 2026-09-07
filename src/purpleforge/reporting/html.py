"""HTML report rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(payload: dict[str, Any], output: str | Path) -> Path:
    """Render the assessment report to a standalone HTML file.

    CSS is inlined in the template so the report can be emailed or attached as a
    single file with no asset directory to keep track of.
    """
    template = _environment().get_template("report.html")
    html = template.render(**payload)

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    return output
