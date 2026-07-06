"""Report renderers. The Markdown renderer is the first shared one — the CLI
prints it today; the CI comment and web report reuse it later, all from the same
self-contained ReadinessReport."""

from __future__ import annotations

from .markdown import render_markdown

__all__ = ["render_markdown"]
