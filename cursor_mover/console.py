"""Console output helpers (color + consistent formatting).

This module keeps logging concise and user-friendly in interactive runs.
"""

from __future__ import annotations

import os
import sys


try:
    from colorama import just_fix_windows_console  # type: ignore
except ImportError:  # pragma: no cover
    just_fix_windows_console = None


_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_FG_RED = "\x1b[31m"
_FG_GREEN = "\x1b[32m"
_FG_YELLOW = "\x1b[33m"
_FG_CYAN = "\x1b[36m"
_FG_GRAY = "\x1b[90m"

_INITIALIZED = False


def init_console() -> None:
    """Initializes console for ANSI color support (especially on Windows)."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    _INITIALIZED = True
    if just_fix_windows_console is None:
        return
    try:
        just_fix_windows_console()
    except Exception:
        # ! Coloring must never break functionality.
        return


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR", "").strip():
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def style(text: str, *, fg: str | None = None, bold: bool = False, stream=sys.stdout) -> str:
    """Formats text with ANSI colors when supported."""
    init_console()
    if not _supports_color(stream):
        return text
    parts: list[str] = []
    if bold:
        parts.append(_BOLD)
    if fg:
        parts.append(fg)
    parts.append(text)
    parts.append(_RESET)
    return "".join(parts)


def dim(text: str) -> str:
    return style(text, fg=_FG_GRAY, stream=sys.stdout)


def info(text: str) -> None:
    print(style(text, fg=_FG_CYAN, bold=True, stream=sys.stdout), flush=True)


def success(text: str) -> None:
    print(style(text, fg=_FG_GREEN, bold=True, stream=sys.stdout), flush=True)


def warn(text: str) -> None:
    print(style(text, fg=_FG_YELLOW, bold=True, stream=sys.stderr), file=sys.stderr, flush=True)


def error(text: str) -> None:
    print(style(text, fg=_FG_RED, bold=True, stream=sys.stderr), file=sys.stderr, flush=True)

