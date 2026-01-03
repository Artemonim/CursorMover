"""Interactive prompts for CLI/TUI flows."""

from __future__ import annotations

import sys


def is_interactive() -> bool:
    """Returns True when stdin/stdout are interactive terminals."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def prompt_choice(prompt: str, choices: dict[str, str], default: str | None = None) -> str:
    """Prompts user to choose one key from `choices`.

    Args:
        prompt: Prompt text.
        choices: Mapping of key -> description.
        default: Default choice key (must exist in `choices`) or None.

    Returns:
        Selected key.
    """
    if default is not None and default not in choices:
        raise ValueError("Default choice must be present in choices.")

    while True:
        print(prompt)
        for key, desc in choices.items():
            print(f"  [{key}] {desc}")
        suffix = f" (default: {default})" if default is not None else ""
        raw = input(f"Select{suffix}: ").strip()
        if not raw and default is not None:
            return default
        if raw in choices:
            return raw
        print("Invalid choice. Please try again.\n")


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    """Prompts user with a yes/no question.

    Args:
        prompt: Question to ask.
        default: Value used when user presses Enter.

    Returns:
        True for yes, False for no.
    """
    default_str = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.\n")


def prompt_text(prompt: str, default: str | None = None) -> str:
    """Prompts user for free-form text input with optional default."""
    suffix = f" (default: {default})" if default is not None else ""
    while True:
        raw = _strip_wrapping_quotes(input(f"{prompt}{suffix}: ").strip())
        if raw:
            return raw
        if default is not None:
            return _strip_wrapping_quotes(default)
        print("Value is required.\n")


def _strip_wrapping_quotes(text: str) -> str:
    """Strips one layer of matching wrapping quotes.

    This helps when users paste paths with quotes, e.g. "C:\\path\\file".
    """
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("\"", "'"):
        return text[1:-1].strip()
    return text

