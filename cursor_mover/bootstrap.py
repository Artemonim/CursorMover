"""Bootstrap helpers for running CursorMover from a repo checkout.

This module is stdlib-only by design: it runs *before* optional dependencies
like `tqdm` are imported by other modules.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path


_ENV_BOOTSTRAPPED = "CURSOR_MOVER_BOOTSTRAPPED"
_ENV_SKIP_BOOTSTRAP = "CURSOR_MOVER_SKIP_BOOTSTRAP"
_ENV_SKIP_INSTALL = "CURSOR_MOVER_SKIP_INSTALL"


def bootstrap_and_run(argv: list[str]) -> int:
    """Bootstraps venv/deps (when in repo checkout) and runs the CLI."""
    try:
        if os.environ.get(_ENV_SKIP_BOOTSTRAP, "").strip():
            from cursor_mover.cli import main  # pylint: disable=import-outside-toplevel

            return main(argv)

        repo_root = _repo_root_from_package_location()
        if repo_root is None:
            _warn_if_missing_optional_deps()
            from cursor_mover.cli import main  # pylint: disable=import-outside-toplevel

            return main(argv)

        venv_dir = repo_root / ".venv"
        requirements_txt = repo_root / "requirements.txt"

        # * Ensure we run under venv's python when available.
        if not _is_running_in_venv() and not os.environ.get(_ENV_BOOTSTRAPPED, "").strip():
            venv_python = _ensure_venv(repo_root=repo_root, venv_dir=venv_dir)
            return _reexec_with_python(
                python_exe=venv_python,
                argv=argv,
                repo_root=repo_root,
            )

        if not os.environ.get(_ENV_SKIP_INSTALL, "").strip():
            _ensure_requirements_installed(
                python_exe=Path(sys.executable),
                requirements_txt=requirements_txt,
                venv_dir=venv_dir,
            )

        from cursor_mover.cli import main  # pylint: disable=import-outside-toplevel

        return main(argv)
    except KeyboardInterrupt:
        # * Avoid traceback spam on Ctrl+C during venv/pip/bootstrap stages.
        print("\nInterrupted by user (Ctrl+C).", file=sys.stderr, flush=True)
        return 130


def _repo_root_from_package_location() -> Path | None:
    package_dir = Path(__file__).resolve().parent
    candidate = package_dir.parent
    if (candidate / "requirements.txt").is_file() and (candidate / "cursor_mover").is_dir():
        return candidate
    return None


def _is_running_in_venv() -> bool:
    return hasattr(sys, "base_prefix") and sys.prefix != sys.base_prefix


def _venv_python_path(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _ensure_venv(*, repo_root: Path, venv_dir: Path) -> Path:
    venv_python = _venv_python_path(venv_dir)
    if venv_python.exists():
        return venv_python

    print(f"Creating venv: {venv_dir}")
    _run_subprocess([sys.executable, "-m", "venv", str(venv_dir)], cwd=repo_root)

    if not venv_python.exists():
        raise FileNotFoundError(f"Venv created but python not found: {venv_python}")
    return venv_python


def _ensure_requirements_installed(
    *,
    python_exe: Path,
    requirements_txt: Path,
    venv_dir: Path,
) -> None:
    if not requirements_txt.exists():
        return

    marker_dir = venv_dir / ".cursor_mover"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / "requirements.sha256"
    req_hash = hashlib.sha256(requirements_txt.read_bytes()).hexdigest()

    if marker.exists() and marker.read_text(encoding="utf-8").strip() == req_hash:
        return

    print("Installing dependencies from requirements.txt...")
    result = _run_subprocess(
        [
            str(python_exe),
            "-m",
            "pip",
            "--disable-pip-version-check",
            "--quiet",
            "install",
            "--progress-bar",
            "off",
            "-r",
            str(requirements_txt),
        ],
        cwd=requirements_txt.parent,
        capture_output=True,
    )
    if result.returncode != 0:
        tail = _tail_lines(result.stdout or "", 80)
        raise RuntimeError("pip install failed:\n" + tail)

    marker.write_text(req_hash, encoding="utf-8")

def _warn_if_missing_optional_deps() -> None:
    # * Keep this warning short: verbose output is annoying in interactive runs.
    try:
        import tqdm  # noqa: F401

        return
    except ImportError:
        pass

    print(
        "Note: tqdm is not installed; progress bars may be disabled. "
        "Run from repo root with .venv or install requirements.txt.",
        file=sys.stderr,
    )


def _reexec_with_python(*, python_exe: Path, argv: list[str], repo_root: Path) -> int:
    env = dict(os.environ)
    env[_ENV_BOOTSTRAPPED] = "1"

    # * Ensure repo root is on PYTHONPATH even if user runs from a different cwd.
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(repo_root) if not existing else (str(repo_root) + os.pathsep + existing)

    cmd = [str(python_exe), "-m", "cursor_mover", *argv]
    result = subprocess.run(cmd, env=env, cwd=Path.cwd(), check=False)
    return result.returncode


def _run_subprocess(
    cmd: list[str],
    *,
    cwd: Path,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    kwargs: dict = {"cwd": str(cwd), "check": False, "text": True}
    if capture_output:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.STDOUT
    return subprocess.run(cmd, **kwargs)  # type: ignore[arg-type]


def _tail_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text.strip()
    return "\n".join(lines[-max_lines:]).strip()

