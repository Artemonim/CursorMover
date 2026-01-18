"""Text UI menu for running CursorMover without CLI arguments."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cursor_mover.console import info
from cursor_mover.prompts import prompt_choice, prompt_text, prompt_yes_no


@dataclass(frozen=True, slots=True)
class TuiRunConfig:
    cmd: str
    cursor_user_dir: Path | None
    src: Path | None
    dst: Path | None
    overwrite_dst: bool
    overwrite_workspace_storage: bool
    merge_workspace_storage: bool
    unsafe_db: bool
    assume_yes: bool
    delete_sources: bool
    doctor_all: bool
    doctor_fix_all: bool
    doctor_delete_legacy: bool
    doctor_check_payloads: bool


def run_tui() -> TuiRunConfig | None:
    """Runs an interactive menu and returns the selected configuration."""
    info("CursorMover")
    print()

    cmd = prompt_choice(
        "What do you want to do?",
        {
            "1": "Copy workspace folder + clone Cursor chats (copy)",
            "2": "Move workspace folder + migrate Cursor chats (move)",
            "3": "Inspect workspace mapping (doctor)",
            "4": "Merge chat state from other workspaceStorage entries (merge)",
            "0": "Exit",
        },
        default="1",
    )
    if cmd == "0":
        return None

    cursor_user_dir_raw = prompt_text("Cursor User dir (leave empty for auto)", default="")
    cursor_user_dir = Path(cursor_user_dir_raw).resolve() if cursor_user_dir_raw else None

    if cmd == "3":
        scope = prompt_choice(
            "Doctor scope?",
            {
                "1": "Single workspace path",
                "2": "All workspaceStorage entries (global scan)",
            },
            default="1",
        )
        if scope == "1":
            path_raw = prompt_text("Workspace folder path", default=str(Path.cwd()))
            return TuiRunConfig(
                cmd="doctor",
                cursor_user_dir=cursor_user_dir,
                src=Path(path_raw).resolve(),
                dst=None,
                overwrite_dst=False,
                overwrite_workspace_storage=False,
                merge_workspace_storage=False,
                unsafe_db=False,
                assume_yes=False,
                delete_sources=False,
                doctor_all=False,
                doctor_fix_all=False,
                doctor_delete_legacy=False,
                doctor_check_payloads=True,
            )
        fix_all = prompt_yes_no(
            "Merge duplicate workspaceStorage entries? (--fix-all)", default=False
        )
        delete_legacy = prompt_yes_no(
            "Delete legacy workspaceStorage entries? (--delete-legacy)", default=False
        )
        check_payloads = prompt_yes_no(
            "Check chat payloads (may be slow)? (--check-payloads)", default=True
        )
        assume_yes = False
        if fix_all or delete_legacy:
            assume_yes = prompt_yes_no("Auto-confirm prompts? (--yes)", default=False)
        return TuiRunConfig(
            cmd="doctor",
            cursor_user_dir=cursor_user_dir,
            src=None,
            dst=None,
            overwrite_dst=False,
            overwrite_workspace_storage=False,
            merge_workspace_storage=False,
            unsafe_db=False,
            assume_yes=assume_yes,
            delete_sources=False,
            doctor_all=True,
            doctor_fix_all=fix_all,
            doctor_delete_legacy=delete_legacy,
            doctor_check_payloads=check_payloads,
        )

    if cmd == "4":
        path_raw = prompt_text("Workspace folder path to merge into", default=str(Path.cwd()))
        assume_yes = prompt_yes_no("Auto-confirm prompts? (--yes)", default=False)
        delete_sources = prompt_yes_no(
            "Delete merged source workspaceStorage folders? (--delete-sources)", default=False
        )
        return TuiRunConfig(
            cmd="merge",
            cursor_user_dir=cursor_user_dir,
            src=Path(path_raw).resolve(),
            dst=None,
            overwrite_dst=False,
            overwrite_workspace_storage=False,
            merge_workspace_storage=False,
            unsafe_db=False,
            assume_yes=assume_yes,
            delete_sources=delete_sources,
            doctor_all=False,
            doctor_fix_all=False,
            doctor_delete_legacy=False,
            doctor_check_payloads=True,
        )

    src_raw = prompt_text("Source folder", default=str(Path.cwd()))
    dst_raw = prompt_text("Destination folder")

    overwrite_dst = prompt_yes_no("Overwrite destination folder if it exists?", default=False)
    ws_action = prompt_choice(
        "If destination workspaceStorage/<id> already exists, what should happen?",
        {
            "a": "Abort (do not touch existing destination workspaceStorage)",
            "m": "Merge source chats into existing destination (preserve destination chats)",
            "o": "Overwrite destination workspaceStorage (delete and replace)",
        },
        default="a",
    )
    unsafe_db = prompt_yes_no(
        "Proceed even if Cursor DB appears locked? (UnsafeDB)", default=False
    )

    return TuiRunConfig(
        cmd="copy" if cmd == "1" else "move",
        cursor_user_dir=cursor_user_dir,
        src=Path(src_raw).resolve(),
        dst=Path(dst_raw).resolve(),
        overwrite_dst=overwrite_dst,
        overwrite_workspace_storage=ws_action == "o",
        merge_workspace_storage=ws_action == "m",
        unsafe_db=unsafe_db,
        assume_yes=False,
        delete_sources=False,
        doctor_all=False,
        doctor_fix_all=False,
        doctor_delete_legacy=False,
        doctor_check_payloads=True,
    )

