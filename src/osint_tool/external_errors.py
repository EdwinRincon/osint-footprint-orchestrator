"""Domain errors raised while invoking external tools."""

from __future__ import annotations


class ExternalToolError(RuntimeError):
    """An external tool failed or could not be run."""


class ToolNotFoundError(ExternalToolError):
    """An external tool is not installed."""
