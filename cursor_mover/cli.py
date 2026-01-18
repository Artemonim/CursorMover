"""CLI for CursorMover."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cursor_mover.console import error, info, success, warn
from cursor_mover.copying import CopyStats, copy_tree_with_progress
from cursor_mover.cursor_paths import default_cursor_user_dir, global_storage_dir
from cursor_mover.locks import WorkspaceStorageLockedError, assert_paths_unlocked
from cursor_mover.merge import MergeResult, merge_workspace_state, read_kv
from cursor_mover.merge import _ensure_tables_exist  # pylint: disable=protected-access
from cursor_mover.prompts import is_interactive, prompt_choice, prompt_yes_no
from cursor_mover.tui import run_tui
from cursor_mover.workspace_id import compute_folder_workspace_id
from cursor_mover.workspace_storage import (
    WorkspaceStorageEntry,
    iter_workspace_storage_entries,
    find_workspace_storage_id_for_folder,
    workspace_db_paths,
    workspace_storage_dir,
)
from cursor_mover.workspace_uri import folder_uri_to_path, path_to_folder_uri


def main(argv: list[str] | None = None) -> int:
    try:
        if argv is None:
            argv = sys.argv[1:]
        if not argv and is_interactive():
            tui_cfg = run_tui()
            if tui_cfg is None:
                return 0
            argv = _tui_config_to_argv(tui_cfg)

        parser = argparse.ArgumentParser(prog="cursor-mover")
        parser.add_argument(
            "--cursor-user-dir",
            type=Path,
            default=None,
            help="Override Cursor User directory (default: auto-detect).",
        )

        sub = parser.add_subparsers(dest="cmd", required=True)

        doctor = sub.add_parser("doctor", help="Show derived workspace ids and Cursor storage mapping.")
        doctor_scope = doctor.add_mutually_exclusive_group(required=True)
        doctor_scope.add_argument("--path", type=Path, help="Workspace folder path.")
        doctor_scope.add_argument(
            "--all",
            action="store_true",
            help="Scan all workspaceStorage entries (duplicates + legacy).",
        )
        doctor.add_argument(
            "--fix-all",
            action="store_true",
            help="Merge duplicate workspaceStorage entries for all folders (requires --all).",
        )
        doctor.add_argument(
            "--delete-legacy",
            action="store_true",
            help="Delete workspaceStorage entries whose folders no longer exist (requires --all).",
        )
        doctor.add_argument(
            "--check-payloads",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Check chat payload keys in workspace/global storage (may be slow).",
        )
        doctor.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm prompts for --fix-all / --delete-legacy.",
        )

        merge_cmd = sub.add_parser(
            "merge",
            help="Merge chat state from other workspaceStorage entries for the same folder URI into the current one.",
        )
        merge_cmd.add_argument("--path", type=Path, required=True, help="Workspace folder path to merge into.")
        merge_cmd.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm interactive prompts.",
        )
        merge_cmd.add_argument(
            "--delete-sources",
            action="store_true",
            help="Delete merged source workspaceStorage folders after successful merge.",
        )

        copy_cmd = sub.add_parser("copy", help="Copy a workspace folder and clone its Cursor chat history (mode C).")
        copy_cmd.add_argument("--src", type=Path, required=True, help="Source folder.")
        copy_cmd.add_argument("--dst", type=Path, required=True, help="Destination folder.")
        copy_cmd.add_argument(
            "--overwrite-dst",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination folder if it already exists.",
        )
        copy_cmd.add_argument(
            "--overwrite-workspace-storage",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination workspaceStorage/<id> if it already exists.",
        )
        copy_cmd.add_argument(
            "--merge-workspace-storage",
            action="store_true",
            help=(
                "If destination workspaceStorage/<id> already exists, merge source chat state into it "
                "(preserve any destination chats) instead of overwriting."
            ),
        )
        copy_cmd.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm interactive prompts (overwrite/unsafe).",
        )
        copy_cmd.add_argument(
            "--unsafe-db",
            "-UnsafeDB",
            "--unlock",
            "-Unlock",
            dest="unsafe_db",
            action="store_true",
            help="Ignore workspaceStorage DB lock check (unsafe; may copy inconsistent state).",
        )

        move_cmd = sub.add_parser(
            "move", help="Move a workspace folder and migrate its Cursor chat history (mode C)."
        )
        move_cmd.add_argument("--src", type=Path, required=True, help="Source folder.")
        move_cmd.add_argument("--dst", type=Path, required=True, help="Destination folder.")
        move_cmd.add_argument(
            "--overwrite-dst",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination folder if it already exists.",
        )
        move_cmd.add_argument(
            "--overwrite-workspace-storage",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Overwrite destination workspaceStorage/<id> if it already exists.",
        )
        move_cmd.add_argument(
            "--merge-workspace-storage",
            action="store_true",
            help=(
                "If destination workspaceStorage/<id> already exists, merge source chat state into it "
                "(preserve any destination chats) instead of overwriting."
            ),
        )
        move_cmd.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm interactive prompts (overwrite/unsafe).",
        )
        move_cmd.add_argument(
            "--unsafe-db",
            "-UnsafeDB",
            "--unlock",
            "-Unlock",
            dest="unsafe_db",
            action="store_true",
            help="Ignore workspaceStorage DB lock check (unsafe; may copy inconsistent state).",
        )

        repair_meta = sub.add_parser(
            "repair-metadata",
            help=(
                "Repair workspace chat metadata (composer.composerData) for a folder workspace. "
                "Useful when chats exist but hang on open."
            ),
        )
        repair_meta.add_argument("--path", type=Path, required=True, help="Workspace folder path.")
        repair_meta.add_argument(
            "--mode",
            choices=("safe", "aggressive"),
            default="safe",
            help="Repair mode. safe: only sanitize selected/focused lists. aggressive: also filters allComposers.",
        )
        repair_meta.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm prompts.",
        )

        reset_sel = sub.add_parser(
            "reset-selection",
            help=(
                "Reset chat selection/focus pointers (selectedComposerIds / lastFocusedComposerIds). "
                "Useful when Cursor hangs trying to auto-open a broken chat."
            ),
        )
        reset_sel.add_argument("--path", type=Path, required=True, help="Workspace folder path.")
        reset_sel.add_argument(
            "--yes",
            action="store_true",
            help="Auto-confirm prompts.",
        )

        args = parser.parse_args(argv)
        cursor_user_dir = args.cursor_user_dir or default_cursor_user_dir()

        try:
            if args.cmd == "doctor":
                if args.all:
                    _cmd_doctor_all(
                        cursor_user_dir=cursor_user_dir,
                        fix_all=args.fix_all,
                        delete_legacy=args.delete_legacy,
                        check_payloads=args.check_payloads,
                        assume_yes=args.yes,
                    )
                    return 0
                if args.fix_all or args.delete_legacy:
                    raise ValueError("Use --all with --fix-all / --delete-legacy.")
                _cmd_doctor(cursor_user_dir, args.path, check_payloads=args.check_payloads)
                return 0
            if args.cmd == "merge":
                _cmd_merge(
                    cursor_user_dir=cursor_user_dir,
                    path=args.path,
                    assume_yes=args.yes,
                    delete_sources=args.delete_sources,
                )
                return 0
            if args.cmd == "copy":
                _cmd_copy_mode_c(
                    cursor_user_dir=cursor_user_dir,
                    src=args.src,
                    dst=args.dst,
                    overwrite_dst=args.overwrite_dst,
                    overwrite_workspace_storage=args.overwrite_workspace_storage,
                    merge_workspace_storage=args.merge_workspace_storage,
                    unsafe_db=args.unsafe_db,
                    assume_yes=args.yes,
                )
                return 0
            if args.cmd == "move":
                _cmd_move_mode_c(
                    cursor_user_dir=cursor_user_dir,
                    src=args.src,
                    dst=args.dst,
                    overwrite_dst=args.overwrite_dst,
                    overwrite_workspace_storage=args.overwrite_workspace_storage,
                    merge_workspace_storage=args.merge_workspace_storage,
                    unsafe_db=args.unsafe_db,
                    assume_yes=args.yes,
                )
                return 0
            if args.cmd == "repair-metadata":
                _cmd_repair_metadata(
                    cursor_user_dir=cursor_user_dir,
                    path=args.path,
                    mode=args.mode,
                    assume_yes=args.yes,
                )
                return 0
            if args.cmd == "reset-selection":
                _cmd_reset_selection(
                    cursor_user_dir=cursor_user_dir,
                    path=args.path,
                    assume_yes=args.yes,
                )
                return 0
        except WorkspaceStorageLockedError as exc:
            error(str(exc))
            return 2
        except (FileExistsError, FileNotFoundError, PermissionError, NotADirectoryError, ValueError) as exc:
            error(str(exc))
            return 2
        except OSError as exc:
            # * Handle common Windows "invalid path" user input.
            if getattr(exc, "winerror", None) == 123:
                error(str(exc))
                return 2
            raise

        raise RuntimeError(f"Unhandled command: {args.cmd}")
    except KeyboardInterrupt:
        # * Handle Ctrl+C gracefully in all interactive stages (TUI prompts, copying, etc.).
        print(file=sys.stderr, flush=True)
        warn("Interrupted by user (Ctrl+C).")
        return 130


@dataclass(frozen=True, slots=True)
class WorkspaceDbInspection:
    db_path: Path
    exists: bool
    itemtable_present: bool
    cursor_disk_present: bool
    composer_ids: int | None
    composer_id_list: tuple[str, ...] | None
    composer_payload_missing: int | None
    composer_payload_checked: int | None
    payload_check_reason: str | None
    composer_meta_invalid_selected: int | None
    composer_meta_invalid_focused: int | None
    composer_meta_unknown_selected: int | None
    error: str | None


@dataclass(slots=True)
class GlobalPayloadCache:
    db_path: Path
    con: sqlite3.Connection | None
    cur: sqlite3.Cursor | None
    cache: dict[str, bool]
    error: str | None
    cursor_disk_present: bool
    db_size_bytes: int | None
    db_mtime_s: float | None
    cursor_disk_rows: int | None
    cursor_disk_key_samples: tuple[str, ...] | None
    summary_printed: bool

    @classmethod
    def open(cls, cursor_user_dir: Path) -> "GlobalPayloadCache":
        db_path = global_storage_dir(cursor_user_dir) / "state.vscdb"
        if not db_path.exists():
            return cls(
                db_path=db_path,
                con=None,
                cur=None,
                cache={},
                error="globalStorage state.vscdb missing",
                cursor_disk_present=False,
                db_size_bytes=None,
                db_mtime_s=None,
                cursor_disk_rows=None,
                cursor_disk_key_samples=None,
                summary_printed=False,
            )
        try:
            st = db_path.stat()
            con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
            cur = con.cursor()
            tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            cursor_disk_present = "cursorDiskKV" in tables
            cursor_disk_rows: int | None = None
            samples: tuple[str, ...] | None = None
            if cursor_disk_present:
                try:
                    row = cur.execute("SELECT COUNT(*) FROM cursorDiskKV").fetchone()
                    cursor_disk_rows = int(row[0]) if row else None
                except sqlite3.Error:
                    cursor_disk_rows = None
                try:
                    raw = [r[0] for r in cur.execute("SELECT key FROM cursorDiskKV LIMIT 8")]
                    samples_list: list[str] = []
                    for k in raw:
                        if isinstance(k, bytes):
                            samples_list.append(k.decode("utf-8", errors="ignore"))
                        else:
                            samples_list.append(str(k))
                    samples = tuple(samples_list)
                except sqlite3.Error:
                    samples = None
            return cls(
                db_path=db_path,
                con=con,
                cur=cur,
                cache={},
                error=None,
                cursor_disk_present=cursor_disk_present,
                db_size_bytes=int(st.st_size),
                db_mtime_s=float(st.st_mtime),
                cursor_disk_rows=cursor_disk_rows,
                cursor_disk_key_samples=samples,
                summary_printed=False,
            )
        except sqlite3.Error as exc:
            return cls(
                db_path=db_path,
                con=None,
                cur=None,
                cache={},
                error=str(exc),
                cursor_disk_present=False,
                db_size_bytes=None,
                db_mtime_s=None,
                cursor_disk_rows=None,
                cursor_disk_key_samples=None,
                summary_printed=False,
            )

    def close(self) -> None:
        if self.con is not None:
            self.con.close()

    def missing_count(self, composer_ids: list[str]) -> tuple[int | None, str | None]:
        if not composer_ids:
            return 0, None
        if self.error:
            return None, self.error
        if not self.cursor_disk_present or self.cur is None:
            return None, "global cursorDiskKV table missing"
        if len(composer_ids) > 200:
            return None, "too many chats (" + str(len(composer_ids)) + ")"

        missing = 0
        for cid in composer_ids:
            present = self.cache.get(cid)
            if present is None:
                try:
                    row = self.cur.execute(
                        "SELECT 1 FROM cursorDiskKV WHERE key LIKE ? LIMIT 1",
                        (f"%{cid}%",),
                    ).fetchone()
                except sqlite3.Error as exc:
                    return None, str(exc)
                present = row is not None
                self.cache[cid] = present
            if not present:
                missing += 1
        return missing, None


def _default_runner_command() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    if sys.platform.startswith("win"):
        if (repo_root / "run.ps1").exists():
            return ".\\run.ps1"
    else:
        if (repo_root / "run.sh").exists():
            return "./run.sh"
    return "python -m cursor_mover"


def _format_cli_path(path: Path) -> str:
    raw = str(path)
    if any(ch.isspace() for ch in raw):
        return f"\"{raw}\""
    return raw


def _format_merge_command(path: Path) -> str:
    runner = _default_runner_command()
    return f"{runner} merge --path {_format_cli_path(path)}"


def _format_doctor_all_command(*, fix_all: bool, delete_legacy: bool, assume_yes: bool) -> str:
    runner = _default_runner_command()
    parts = [runner, "doctor", "--all"]
    if fix_all:
        parts.append("--fix-all")
    if delete_legacy:
        parts.append("--delete-legacy")
    if assume_yes:
        parts.append("--yes")
    return " ".join(parts)


def _composer_id_list_from_composer_data(raw: bytes | None) -> list[str]:
    if not raw:
        return []
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return []
    composers = payload.get("allComposers")
    if not isinstance(composers, list):
        return []
    ids: list[str] = []
    seen: set[str] = set()
    for item in composers:
        if not isinstance(item, dict):
            continue
        cid = item.get("composerId")
        if not isinstance(cid, str):
            continue
        if cid in seen:
            continue
        seen.add(cid)
        ids.append(cid)
    return ids


def _read_json_bytes(raw: bytes | None) -> dict | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _extract_id_list(value) -> list[str]:
    """Best-effort conversion of selected/focused ID lists to string ids."""
    if not isinstance(value, list):
        return []
    ids: list[str] = []
    for item in value:
        if isinstance(item, str):
            ids.append(item)
            continue
        if isinstance(item, dict):
            cid = item.get("composerId")
            if isinstance(cid, str):
                ids.append(cid)
    return ids


def _repair_composer_metadata(payload: dict) -> tuple[dict, dict[str, int]]:
    """Repairs composer.composerData structure in-place and reports changes.

    Warning:
        Cursor may change the `allComposers` schema between versions. This
        function can be destructive if that schema does not match expectations.

    This targets known Cursor bugs where selected/focused lists may contain
    invalid items (e.g. objects without composerId), causing UI hangs.
    """
    stats: dict[str, int] = {
        "invalid_selected": 0,
        "invalid_focused": 0,
        "unknown_selected": 0,
        "unknown_focused": 0,
        "dropped_composers": 0,
    }

    composers = payload.get("allComposers")
    if not isinstance(composers, list):
        composers = []
    cleaned_composers: list[dict] = []
    known_ids: set[str] = set()
    for item in composers:
        if not isinstance(item, dict):
            stats["dropped_composers"] += 1
            continue
        cid = item.get("composerId")
        if not isinstance(cid, str) or not cid:
            stats["dropped_composers"] += 1
            continue
        cleaned_composers.append(item)
        known_ids.add(cid)
    payload["allComposers"] = cleaned_composers

    selected_raw = payload.get("selectedComposerIds")
    focused_raw = payload.get("lastFocusedComposerIds")

    selected_ids = _extract_id_list(selected_raw)
    focused_ids = _extract_id_list(focused_raw)

    if isinstance(selected_raw, list):
        stats["invalid_selected"] = sum(1 for x in selected_raw if not isinstance(x, str))
    if isinstance(focused_raw, list):
        stats["invalid_focused"] = sum(1 for x in focused_raw if not isinstance(x, str))

    # Filter to known ids
    selected_filtered = [cid for cid in selected_ids if cid in known_ids]
    focused_filtered = [cid for cid in focused_ids if cid in known_ids]
    stats["unknown_selected"] = max(0, len(selected_ids) - len(selected_filtered))
    stats["unknown_focused"] = max(0, len(focused_ids) - len(focused_filtered))

    payload["selectedComposerIds"] = selected_filtered
    payload["lastFocusedComposerIds"] = focused_filtered
    return payload, stats


def _repair_composer_metadata_safe(payload: dict) -> tuple[dict, dict[str, int]]:
    """Safe repair: do not touch `allComposers`, only sanitize selection lists.

    Strategy:
      - Convert selected/focused arrays to list[str], dropping invalid items.
      - Do NOT filter to known IDs (because schema may differ); just ensure types.
    """
    stats: dict[str, int] = {
        "invalid_selected": 0,
        "invalid_focused": 0,
        "unknown_selected": 0,
        "unknown_focused": 0,
        "dropped_composers": 0,
    }
    selected_raw = payload.get("selectedComposerIds")
    focused_raw = payload.get("lastFocusedComposerIds")

    if isinstance(selected_raw, list):
        stats["invalid_selected"] = sum(
            1 for x in selected_raw if not (isinstance(x, str) or isinstance(x, dict))
        )
    if isinstance(focused_raw, list):
        stats["invalid_focused"] = sum(
            1 for x in focused_raw if not (isinstance(x, str) or isinstance(x, dict))
        )

    payload["selectedComposerIds"] = _extract_id_list(selected_raw)
    payload["lastFocusedComposerIds"] = _extract_id_list(focused_raw)
    return payload, stats


def _count_missing_composer_payloads(
    cur: sqlite3.Cursor,
    composer_ids: list[str],
    tables: list[str],
) -> int | None:
    if not composer_ids:
        return 0
    if not tables:
        return None
    missing = set(composer_ids)
    try:
        for table in tables:
            if not missing:
                break
            for (key,) in cur.execute(f"SELECT key FROM {table}"):
                if not missing:
                    break
                if isinstance(key, bytes):
                    key_text = key.decode("utf-8", errors="ignore")
                else:
                    key_text = str(key)
                for cid in tuple(missing):
                    if cid in key_text:
                        missing.discard(cid)
        return len(missing)
    except sqlite3.Error:
        return None


def _inspect_global_payloads(
    cursor_user_dir: Path,
    composer_ids: list[str],
) -> tuple[int | None, str | None]:
    if not composer_ids:
        return 0, None
    cache = GlobalPayloadCache.open(cursor_user_dir)
    try:
        return cache.missing_count(composer_ids)
    finally:
        cache.close()


def _print_global_payload_check_result(missing: int | None, reason: str | None) -> None:
    if reason:
        warn(f"Global payload check skipped: {reason}")
        return
    if missing is not None and missing > 0:
        warn("Global payload check: missing keys for " + str(missing) + " chat(s)")
        warn(
            "Note: this is a heuristic check (key substring match). "
            "If globalStorage is not empty, Cursor may use a different key format."
        )
        return
    success("Global payload check: keys present")


def _print_global_storage_summary(global_cache: GlobalPayloadCache) -> None:
    size = global_cache.db_size_bytes
    mtime = global_cache.db_mtime_s
    rows = global_cache.cursor_disk_rows
    samples = global_cache.cursor_disk_key_samples
    if size is not None:
        info(f"Global DB size: {size} bytes")
    if mtime is not None:
        info(f"Global DB mtime: {mtime}")
    if rows is not None:
        info(f"Global cursorDiskKV rows: {rows}")
    if samples:
        info("Global cursorDiskKV key samples:")
        for s in samples:
            info("  " + s)


def _inspect_workspace_db(db_path: Path) -> WorkspaceDbInspection:
    if not db_path.exists():
        return WorkspaceDbInspection(
            db_path=db_path,
            exists=False,
            itemtable_present=False,
            cursor_disk_present=False,
            composer_ids=None,
            composer_id_list=None,
            composer_payload_missing=None,
            composer_payload_checked=None,
            payload_check_reason=None,
            composer_meta_invalid_selected=None,
            composer_meta_invalid_focused=None,
            composer_meta_unknown_selected=None,
            error=None,
        )

    try:
        con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return WorkspaceDbInspection(
            db_path=db_path,
            exists=True,
            itemtable_present=False,
            cursor_disk_present=False,
            composer_ids=None,
            composer_id_list=None,
            composer_payload_missing=None,
            composer_payload_checked=None,
            payload_check_reason=None,
            composer_meta_invalid_selected=None,
            composer_meta_invalid_focused=None,
            composer_meta_unknown_selected=None,
            error=str(exc),
        )

    try:
        cur = con.cursor()
        tables = {row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        itemtable_present = "ItemTable" in tables
        cursor_disk_present = "cursorDiskKV" in tables
        composer_ids: int | None = None
        composer_id_list: tuple[str, ...] | None = None
        composer_payload_missing: int | None = None
        composer_payload_checked: int | None = None
        payload_check_reason: str | None = None
        composer_meta_invalid_selected: int | None = None
        composer_meta_invalid_focused: int | None = None
        composer_meta_unknown_selected: int | None = None
        if itemtable_present:
            composer_raw = read_kv(cur, table="ItemTable", key="composer.composerData")
            composer_ids_list = _composer_id_list_from_composer_data(composer_raw)
            composer_id_list = tuple(composer_ids_list)
            composer_ids = len(composer_ids_list)
            parsed = _read_json_bytes(composer_raw)
            if parsed is not None:
                _repaired, stats = _repair_composer_metadata(dict(parsed))
                composer_meta_invalid_selected = stats.get("invalid_selected")
                composer_meta_invalid_focused = stats.get("invalid_focused")
                composer_meta_unknown_selected = stats.get("unknown_selected")
            if composer_id_list:
                composer_payload_checked = len(composer_id_list)
                tables_to_scan: list[str] = []
                if itemtable_present:
                    tables_to_scan.append("ItemTable")
                if cursor_disk_present:
                    tables_to_scan.append("cursorDiskKV")
                if composer_payload_checked > 200:
                    payload_check_reason = "too many chats (" + str(composer_payload_checked) + ")"
                else:
                    composer_payload_missing = _count_missing_composer_payloads(
                        cur, list(composer_id_list), tables_to_scan
                    )
                    if composer_payload_missing is None:
                        payload_check_reason = "payload scan failed"
        return WorkspaceDbInspection(
            db_path=db_path,
            exists=True,
            itemtable_present=itemtable_present,
            cursor_disk_present=cursor_disk_present,
            composer_ids=composer_ids,
            composer_id_list=composer_id_list,
            composer_payload_missing=composer_payload_missing,
            composer_payload_checked=composer_payload_checked,
            payload_check_reason=payload_check_reason,
            composer_meta_invalid_selected=composer_meta_invalid_selected,
            composer_meta_invalid_focused=composer_meta_invalid_focused,
            composer_meta_unknown_selected=composer_meta_unknown_selected,
            error=None,
        )
    except sqlite3.Error as exc:
        return WorkspaceDbInspection(
            db_path=db_path,
            exists=True,
            itemtable_present=False,
            cursor_disk_present=False,
            composer_ids=None,
            composer_id_list=None,
            composer_payload_missing=None,
            composer_payload_checked=None,
            payload_check_reason=None,
            composer_meta_invalid_selected=None,
            composer_meta_invalid_focused=None,
            composer_meta_unknown_selected=None,
            error=str(exc),
        )
    finally:
        con.close()


def _print_workspace_db_inspection(
    cursor_user_dir: Path,
    label: str,
    storage_dir: Path,
    *,
    global_cache: GlobalPayloadCache | None = None,
) -> tuple[WorkspaceDbInspection, int | None, str | None]:
    info(f"WorkspaceStorage entry: {label}")
    db_path = storage_dir / "state.vscdb"
    inspection = _inspect_workspace_db(db_path)
    if not inspection.exists:
        warn(f"Workspace DB missing: {db_path}")
        return inspection, None, None
    if inspection.error:
        warn(f"Workspace DB check failed: {inspection.error}")
        return inspection, None, inspection.error
    if not inspection.itemtable_present:
        warn("Workspace DB missing ItemTable; chat registry is unavailable.")
    if not inspection.cursor_disk_present:
        warn("Workspace DB missing cursorDiskKV; storage may be incomplete.")
    if inspection.composer_ids is None:
        warn("Chat registry not found (composer.composerData).")
        return inspection, None, None
    if inspection.composer_ids == 0:
        warn("No chats found in workspace DB.")
        return inspection, None, None
    info(f"CHAT REGISTRY: {inspection.composer_ids} chat(s)")
    if inspection.composer_meta_invalid_selected:
        warn(f"Metadata: invalid selectedComposerIds items: {inspection.composer_meta_invalid_selected}")
    if inspection.composer_meta_invalid_focused:
        warn(f"Metadata: invalid lastFocusedComposerIds items: {inspection.composer_meta_invalid_focused}")
    if inspection.composer_meta_unknown_selected:
        warn(f"Metadata: selectedComposerIds not present in allComposers: {inspection.composer_meta_unknown_selected}")
    if inspection.composer_payload_missing is None:
        if inspection.payload_check_reason:
            warn(f"Workspace payload check skipped: {inspection.payload_check_reason}")
    elif inspection.composer_payload_missing > 0:
        warn(
            "Workspace payload check: missing keys for "
            + str(inspection.composer_payload_missing)
            + " chat(s)"
        )
        warn("Workspace payloads may be incomplete or stored elsewhere.")
    else:
        success("Workspace payload check: keys present")

    composer_ids = list(inspection.composer_id_list or [])
    if composer_ids:
        if global_cache is not None:
            missing, reason = global_cache.missing_count(composer_ids)
            if global_cache.error is None and not global_cache.summary_printed:
                _print_global_storage_summary(global_cache)
                global_cache.summary_printed = True
        else:
            missing, reason = _inspect_global_payloads(cursor_user_dir, composer_ids)
        _print_global_payload_check_result(missing, reason)
        return inspection, missing, reason
    return inspection, None, None


def _try_folder_uri_to_path(folder_uri: str) -> Path | None:
    try:
        return folder_uri_to_path(folder_uri)
    except ValueError:
        return None


def _cmd_doctor(
    cursor_user_dir: Path,
    folder: Path,
    *,
    check_payloads: bool,
    allow_repair_prompt: bool = True,
) -> None:
    folder = folder.resolve()
    folder_uri = path_to_folder_uri(folder)
    computed = compute_folder_workspace_id(folder)
    entries = [e for e in iter_workspace_storage_entries(cursor_user_dir) if e.folder_uri == folder_uri]
    found_ids = sorted({e.workspace_id for e in entries})
    found_str = ", ".join(found_ids) if found_ids else "None"

    info(f"Cursor User dir: {cursor_user_dir}")
    info(f"Folder: {folder}")
    info(f"Folder URI: {folder_uri}")
    info(f"WorkspaceStorage ids (found by workspace.json): {found_str}")
    info(f"WorkspaceStorage id (computed): {computed.workspace_id}")
    info(f"Computed fsPath: {computed.fs_path_for_hash}")
    info(f"Computed stat salt: {computed.stat_salt}")

    computed_storage = workspace_storage_dir(cursor_user_dir, computed.workspace_id)
    if computed_storage.exists() and not (computed_storage / "workspace.json").exists():
        warn("Computed workspaceStorage entry exists, but workspace.json is missing.")

    if found_ids and computed.workspace_id not in found_ids:
        warn(
            "Computed workspaceStorage id does not match ids found by workspace.json. "
            "Cursor may create a new workspaceStorage entry for this folder."
        )
        warn("If chats appear missing, open the folder once in Cursor, then run merge to consolidate.")
        warn(f"Suggested fix (after opening once): {_format_merge_command(folder)}")

    if len(found_ids) > 1:
        warn("Multiple workspaceStorage entries found for this folder URI. Chat history may appear split.")
        warn(f"Suggested fix: {_format_merge_command(folder)}")

    lock_storage: Path | None = None
    if computed_storage.exists():
        lock_storage = computed_storage
    elif found_ids:
        lock_storage = workspace_storage_dir(cursor_user_dir, found_ids[0])

    if lock_storage is not None:
        dbs = list(workspace_db_paths(lock_storage))
        try:
            assert_paths_unlocked(dbs)
        except WorkspaceStorageLockedError as exc:
            error("LOCK CHECK: FAILED\n" + str(exc))
            return
        success("LOCK CHECK: OK")
    else:
        warn("No workspaceStorage entry found for this folder. Open it in Cursor and retry.")
        return

    inspection_targets: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for entry in entries:
        storage_dir = entry.storage_dir.resolve()
        if storage_dir in seen:
            continue
        inspection_targets.append((entry.workspace_id, storage_dir))
        seen.add(storage_dir)
    if computed_storage.exists():
        storage_dir = computed_storage.resolve()
        if storage_dir not in seen:
            inspection_targets.append((f"{computed.workspace_id} (computed)", storage_dir))

    primary_storage = computed_storage if computed_storage.exists() else None
    if primary_storage is None and inspection_targets:
        primary_storage = inspection_targets[0][1]

    primary_inspection: WorkspaceDbInspection | None = None
    primary_global_missing: int | None = None

    global_cache: GlobalPayloadCache | None = None
    if check_payloads:
        global_cache = GlobalPayloadCache.open(cursor_user_dir)
    try:
        for label, storage_dir in inspection_targets:
            if not check_payloads:
                continue
            inspection, global_missing, _global_reason = _print_workspace_db_inspection(
                cursor_user_dir,
                label,
                storage_dir,
                global_cache=global_cache,
            )
            if primary_storage is not None and storage_dir.resolve() == primary_storage.resolve():
                primary_inspection = inspection
                primary_global_missing = global_missing
    finally:
        if global_cache is not None:
            global_cache.close()

    if not check_payloads:
        return

    if (
        allow_repair_prompt
        and check_payloads
        and primary_inspection is not None
        and primary_inspection.composer_ids
    ):
        if (
            is_interactive()
            and (
                (primary_inspection.composer_meta_invalid_selected or 0) > 0
                or (primary_inspection.composer_meta_invalid_focused or 0) > 0
                or (primary_inspection.composer_meta_unknown_selected or 0) > 0
            )
            and prompt_yes_no(
                "Metadata looks corrupted. Attempt to repair composer.composerData now?",
                default=True,
            )
        ):
            _cmd_repair_metadata(
                cursor_user_dir=cursor_user_dir,
                path=folder,
                mode="safe",
                assume_yes=True,
            )
            success("Metadata repair attempt complete. Re-checking...")
            _cmd_doctor(
                cursor_user_dir,
                folder,
                check_payloads=check_payloads,
                allow_repair_prompt=False,
            )
            return

        missing_workspace = primary_inspection.composer_payload_missing
        missing_global = primary_global_missing
        has_missing = (
            (missing_workspace is not None and missing_workspace > 0)
            or (missing_global is not None and missing_global > 0)
        )
        if not has_missing:
            return
        if len(entries) > 1:
            if not is_interactive():
                warn("Non-interactive session: run merge to attempt repair.")
                warn(f"Suggested fix: {_format_merge_command(folder)}")
                return
            if prompt_yes_no("Attempt to merge duplicate workspaceStorage entries now?", default=True):
                result = _merge_duplicates_for_folder(
                    cursor_user_dir=cursor_user_dir,
                    folder_uri=folder_uri,
                    folder_path=folder,
                    entries=entries,
                )
                if result is None:
                    warn("Nothing was merged.")
                    return
                success("Repair attempt complete. Re-checking...")
                _cmd_doctor(
                    cursor_user_dir,
                    folder,
                    check_payloads=check_payloads,
                    allow_repair_prompt=False,
                )
                return
            return

        if not is_interactive():
            warn("Non-interactive session: run a global scan to attempt repair.")
            warn(f"Suggested fix: {_format_doctor_all_command(fix_all=True, delete_legacy=False, assume_yes=False)}")
            return
        if prompt_yes_no(
            "No duplicates found for this folder. Run global scan + merge duplicates?",
            default=True,
        ):
            _cmd_doctor_all(
                cursor_user_dir=cursor_user_dir,
                fix_all=True,
                delete_legacy=False,
                check_payloads=check_payloads,
                assume_yes=False,
            )
            success("Global repair attempt complete. Re-checking...")
            _cmd_doctor(
                cursor_user_dir,
                folder,
                check_payloads=check_payloads,
                allow_repair_prompt=False,
            )
            return


def _confirm_doctor_action(action: str, count: int, assume_yes: bool) -> bool:
    if count <= 0:
        return False
    if assume_yes:
        return True
    if not is_interactive():
        warn(f"Non-interactive session: use --yes to {action.lower()}.")
        return False
    return prompt_yes_no(f"{action} ({count} item(s))?", default=False)


def _merge_duplicates_for_folder(
    *,
    cursor_user_dir: Path,
    folder_uri: str,
    folder_path: Path,
    entries: list[WorkspaceStorageEntry],
) -> MergeResult | None:
    computed = compute_folder_workspace_id(folder_path)
    dst_storage_dir = workspace_storage_dir(cursor_user_dir, computed.workspace_id)
    if not dst_storage_dir.exists():
        warn(
            "Destination workspaceStorage entry does not exist. "
            "Open the folder in Cursor once, then retry."
        )
        return None

    dst_db = dst_storage_dir / "state.vscdb"
    if not dst_db.exists():
        warn(f"Destination DB missing: {dst_db}")
        return None

    src_db_paths: list[Path] = []
    for entry in entries:
        if entry.workspace_id == computed.workspace_id:
            continue
        src_db = entry.storage_dir / "state.vscdb"
        if src_db.exists():
            src_db_paths.append(src_db)
        else:
            warn(f"Source DB missing: {src_db}")

    if not src_db_paths:
        return None

    result = merge_workspace_state(dst_db_path=dst_db, src_db_paths=src_db_paths)
    _write_workspace_storage_meta(dst_storage_dir, folder_uri)
    return result


def _merge_all_duplicates(
    *,
    cursor_user_dir: Path,
    duplicates: dict[str, list[WorkspaceStorageEntry]],
    folder_paths: dict[str, Path],
) -> None:
    merged = 0
    skipped = 0
    failed = 0
    for folder_uri, entries in duplicates.items():
        folder_path = folder_paths.get(folder_uri)
        if folder_path is None or not folder_path.exists() or not folder_path.is_dir():
            warn(f"Skipping missing folder: {folder_uri}")
            skipped += 1
            continue
        try:
            result = _merge_duplicates_for_folder(
                cursor_user_dir=cursor_user_dir,
                folder_uri=folder_uri,
                folder_path=folder_path,
                entries=entries,
            )
        except (FileNotFoundError, RuntimeError, WorkspaceStorageLockedError, ValueError) as exc:
            warn(f"Merge failed for {folder_path}: {exc}")
            failed += 1
            continue
        if result is None:
            skipped += 1
            continue
        merged += 1
        success(f"Merged workspaceStorage for: {folder_path}")
        info(
            "Inserted keys: ItemTable="
            + str(result.inserted_itemtable_keys)
            + " cursorDiskKV="
            + str(result.inserted_cursordiskkv_keys)
        )
        info(f"Composer entries: {result.composer_ids_before} -> {result.composer_ids_after}")
        info(f"Backup: {result.backup_path}")

    if merged:
        success(f"Merged workspaces: {merged}")
    if skipped:
        warn(f"Skipped workspaces: {skipped}")
    if failed:
        warn(f"Failed merges: {failed}")


def _delete_legacy_entries(
    legacy_entries: list[tuple[WorkspaceStorageEntry, Path]],
    assume_yes: bool,
) -> None:
    if not legacy_entries:
        info("No legacy workspaceStorage entries found.")
        return
    if not _confirm_doctor_action("Delete legacy workspaceStorage entries", len(legacy_entries), assume_yes):
        return

    deleted = 0
    skipped = 0
    for entry, _folder_path in legacy_entries:
        if not entry.storage_dir.exists():
            skipped += 1
            continue
        try:
            assert_paths_unlocked(workspace_db_paths(entry.storage_dir))
        except WorkspaceStorageLockedError as exc:
            warn(f"Skipping locked entry: {entry.storage_dir}")
            warn(str(exc))
            skipped += 1
            continue
        _robust_rmtree(entry.storage_dir)
        deleted += 1

    if deleted:
        success(f"Deleted legacy entries: {deleted}")
    if skipped:
        warn(f"Skipped legacy entries: {skipped}")


def _cmd_doctor_all(
    *,
    cursor_user_dir: Path,
    fix_all: bool,
    delete_legacy: bool,
    check_payloads: bool,
    assume_yes: bool,
) -> None:
    info(f"Cursor User dir: {cursor_user_dir}")
    entries = list(iter_workspace_storage_entries(cursor_user_dir))
    info(f"WorkspaceStorage entries: {len(entries)}")
    if not entries:
        warn("No workspaceStorage entries found.")
        return

    unresolved_entries: list[WorkspaceStorageEntry] = []
    entries_with_uri: list[tuple[WorkspaceStorageEntry, Path]] = []
    legacy_entries: list[tuple[WorkspaceStorageEntry, Path]] = []
    missing_db_entries: list[WorkspaceStorageEntry] = []

    for entry in entries:
        if not entry.folder_uri:
            unresolved_entries.append(entry)
        else:
            folder_path = _try_folder_uri_to_path(entry.folder_uri)
            if folder_path is None:
                unresolved_entries.append(entry)
            else:
                entries_with_uri.append((entry, folder_path))
                if not folder_path.exists() or not folder_path.is_dir():
                    legacy_entries.append((entry, folder_path))

        if not (entry.storage_dir / "state.vscdb").exists():
            missing_db_entries.append(entry)

    grouped: dict[str, list[WorkspaceStorageEntry]] = {}
    folder_paths: dict[str, Path] = {}
    for entry, folder_path in entries_with_uri:
        grouped.setdefault(entry.folder_uri, []).append(entry)
        folder_paths.setdefault(entry.folder_uri, folder_path)

    duplicates = {uri: items for uri, items in grouped.items() if len(items) > 1}

    if unresolved_entries:
        warn(f"Entries with missing/invalid workspace.json: {len(unresolved_entries)}")
        for entry in unresolved_entries:
            info(f"Unresolved entry: {entry.workspace_id} -> {entry.storage_dir}")

    if missing_db_entries:
        warn(f"Entries missing state.vscdb: {len(missing_db_entries)}")
        for entry in missing_db_entries:
            info(f"Missing DB: {entry.workspace_id} -> {entry.storage_dir}")

    if legacy_entries:
        warn(f"Legacy entries (folder missing): {len(legacy_entries)}")
        for entry, folder_path in legacy_entries:
            info(f"Legacy entry: {entry.workspace_id} -> {folder_path}")

    if duplicates:
        warn(f"Duplicate workspaceStorage entries: {len(duplicates)}")
        for folder_uri, items in duplicates.items():
            folder_path = folder_paths.get(folder_uri)
            ids = ", ".join(sorted(e.workspace_id for e in items))
            if folder_path is not None:
                info(f"Folder: {folder_path}")
            info(f"Folder URI: {folder_uri}")
            info(f"WorkspaceStorage ids: {ids}")
            if folder_path is not None and folder_path.exists() and folder_path.is_dir():
                warn(f"Suggested fix: {_format_merge_command(folder_path)}")
            else:
                warn("Folder path is missing; cannot merge automatically.")

        warn(
            "Suggested fix (all): "
            + _format_doctor_all_command(
                fix_all=True,
                delete_legacy=False,
                assume_yes=assume_yes,
            )
        )

    if fix_all:
        if not duplicates:
            info("Nothing to merge: no duplicate workspaceStorage entries found.")
        elif _confirm_doctor_action(
            "Merge all duplicate workspaceStorage entries",
            len(duplicates),
            assume_yes,
        ):
            _merge_all_duplicates(
                cursor_user_dir=cursor_user_dir,
                duplicates=duplicates,
                folder_paths=folder_paths,
            )

    if delete_legacy:
        _delete_legacy_entries(legacy_entries, assume_yes)

    if not check_payloads:
        return

    info("Chat payload checks:")
    global_cache = GlobalPayloadCache.open(cursor_user_dir)
    try:
        for entry in entries:
            folder_path = None
            if entry.folder_uri:
                folder_path = _try_folder_uri_to_path(entry.folder_uri)
            label = entry.workspace_id
            if folder_path is not None:
                info(f"Folder: {folder_path}")
            if entry.folder_uri:
                info(f"Folder URI: {entry.folder_uri}")
            _print_workspace_db_inspection(
                cursor_user_dir,
                label,
                entry.storage_dir,
                global_cache=global_cache,
            )
    finally:
        global_cache.close()

def _cmd_merge(
    *,
    cursor_user_dir: Path,
    path: Path,
    assume_yes: bool,
    delete_sources: bool,
) -> None:
    folder = path.resolve()
    folder_uri = path_to_folder_uri(folder)
    dst_id = compute_folder_workspace_id(folder).workspace_id
    dst_storage = workspace_storage_dir(cursor_user_dir, dst_id)
    dst_db = dst_storage / "state.vscdb"

    if not dst_storage.exists():
        raise FileNotFoundError(
            "Destination workspaceStorage folder does not exist. "
            "Open the folder once in Cursor or run copy/move first."
        )

    # * Find other workspaceStorage entries that refer to the same folder URI.
    sources: list[Path] = []
    for entry in iter_workspace_storage_entries(cursor_user_dir):
        if entry.folder_uri != folder_uri:
            continue
        if entry.workspace_id == dst_id:
            continue
        candidate = entry.storage_dir / "state.vscdb"
        if candidate.exists():
            sources.append(candidate)

    if not sources:
        info("Nothing to merge: no other workspaceStorage entries found for this folder URI.")
        return

    # * Require unlocked DBs; merging writes and needs safe file swaps.
    _require_unlocked_for_merge(dst_db, sources)

    result = merge_workspace_state(dst_db_path=dst_db, src_db_paths=sources)
    success("OK")
    info(f"Merged sources: {len(result.sources)}")
    info(
        "Inserted keys: ItemTable="
        + str(result.inserted_itemtable_keys)
        + " cursorDiskKV="
        + str(result.inserted_cursordiskkv_keys)
    )
    info(f"Composer entries: {result.composer_ids_before} -> {result.composer_ids_after}")
    info(f"Backup: {result.backup_path}")

    if delete_sources:
        if not assume_yes and is_interactive():
            if not prompt_yes_no("Delete merged source workspaceStorage folders?", default=False):
                return
        for src_db in result.sources:
            _robust_rmtree(src_db.parent)
        info("Deleted merged source workspaceStorage folders.")


def _cmd_repair_metadata(
    *,
    cursor_user_dir: Path,
    path: Path,
    mode: str,
    assume_yes: bool,
) -> None:
    folder = path.resolve()
    folder_uri = path_to_folder_uri(folder)
    dst_id = compute_folder_workspace_id(folder).workspace_id
    storage_dir = workspace_storage_dir(cursor_user_dir, dst_id)
    db_path = storage_dir / "state.vscdb"

    if not storage_dir.exists():
        raise FileNotFoundError(
            "Destination workspaceStorage folder does not exist. "
            "Open the folder once in Cursor or run copy/move first."
        )
    if not db_path.exists():
        raise FileNotFoundError(db_path)

    # * Require unlocked DB to safely swap/backup.
    _require_unlocked_for_merge(db_path, [])

    if not assume_yes and is_interactive():
        if not prompt_yes_no(
            f"Repair composer.composerData metadata ({mode})? (creates a backup)",
            default=False,
        ):
            return

    ts = time.strftime("%Y%m%d-%H%M%S")
    tmp_db = db_path.with_name(f"{db_path.name}.repair-tmp-{ts}")
    backup_db = db_path.with_name(f"{db_path.name}.prerepair-{ts}")

    src_con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tmp_con = sqlite3.connect(tmp_db.as_posix())
        try:
            src_con.backup(tmp_con)
        finally:
            tmp_con.close()
    finally:
        src_con.close()

    con = sqlite3.connect(tmp_db.as_posix())
    try:
        cur = con.cursor()
        _ensure_tables_exist(cur)
        raw = read_kv(cur, table="ItemTable", key="composer.composerData")
        payload = _read_json_bytes(raw)
        if payload is None:
            warn("composer.composerData is missing or not valid JSON; nothing to repair.")
            return

        raw_before = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ids_before = len(_composer_id_list_from_composer_data(raw_before))

        if mode == "aggressive":
            repaired, stats = _repair_composer_metadata(payload)
        else:
            repaired, stats = _repair_composer_metadata_safe(payload)

        repaired_raw = json.dumps(repaired, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ids_after = len(_composer_id_list_from_composer_data(repaired_raw))
        if ids_after < ids_before:
            raise RuntimeError(
                "Repair would reduce visible chats ("
                + str(ids_before)
                + " -> "
                + str(ids_after)
                + "). Aborting to protect history. Use --mode aggressive only if you know it is safe."
            )
        cur.execute(
            "INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)",
            ("composer.composerData", repaired_raw),
        )
        check = cur.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {check[0] if check else 'unknown'}")
        con.commit()
    finally:
        con.close()

    shutil.move(db_path, backup_db)
    shutil.move(tmp_db, db_path)
    # * Remove any WAL/SHM files to avoid stale state replay.
    for suffix in ("-wal", "-shm"):
        try:
            (db_path.with_name(db_path.name + suffix)).unlink(missing_ok=True)  # type: ignore[attr-defined]
        except TypeError:
            # Python < 3.8 compatibility (not expected here, but keep safe).
            p = db_path.with_name(db_path.name + suffix)
            if p.exists():
                p.unlink()
    _write_workspace_storage_meta(storage_dir, folder_uri)
    success("OK")
    info(f"Backup: {backup_db}")
    info(
        "Metadata repair stats: invalid_selected="
        + str(stats.get("invalid_selected"))
        + " invalid_focused="
        + str(stats.get("invalid_focused"))
        + " unknown_selected="
        + str(stats.get("unknown_selected"))
    )


def _cmd_reset_selection(*, cursor_user_dir: Path, path: Path, assume_yes: bool) -> None:
    folder = path.resolve()
    folder_uri = path_to_folder_uri(folder)
    dst_id = compute_folder_workspace_id(folder).workspace_id
    storage_dir = workspace_storage_dir(cursor_user_dir, dst_id)
    db_path = storage_dir / "state.vscdb"

    if not storage_dir.exists():
        raise FileNotFoundError(
            "Destination workspaceStorage folder does not exist. "
            "Open the folder once in Cursor or run copy/move first."
        )
    if not db_path.exists():
        raise FileNotFoundError(db_path)

    _require_unlocked_for_merge(db_path, [])
    if not assume_yes and is_interactive():
        if not prompt_yes_no("Reset selected/focused chat pointers? (creates a backup)", default=False):
            return

    ts = time.strftime("%Y%m%d-%H%M%S")
    tmp_db = db_path.with_name(f"{db_path.name}.reset-tmp-{ts}")
    backup_db = db_path.with_name(f"{db_path.name}.prereset-{ts}")

    src_con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tmp_con = sqlite3.connect(tmp_db.as_posix())
        try:
            src_con.backup(tmp_con)
        finally:
            tmp_con.close()
    finally:
        src_con.close()

    con = sqlite3.connect(tmp_db.as_posix())
    try:
        cur = con.cursor()
        _ensure_tables_exist(cur)
        raw = read_kv(cur, table="ItemTable", key="composer.composerData")
        payload = _read_json_bytes(raw)
        if payload is None:
            warn("composer.composerData is missing or not valid JSON; nothing to reset.")
            return
        payload["selectedComposerIds"] = []
        payload["lastFocusedComposerIds"] = []
        repaired_raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        cur.execute(
            "INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)",
            ("composer.composerData", repaired_raw),
        )
        check = cur.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {check[0] if check else 'unknown'}")
        con.commit()
    finally:
        con.close()

    shutil.move(db_path, backup_db)
    shutil.move(tmp_db, db_path)
    for suffix in ("-wal", "-shm"):
        try:
            (db_path.with_name(db_path.name + suffix)).unlink(missing_ok=True)  # type: ignore[attr-defined]
        except TypeError:
            p = db_path.with_name(db_path.name + suffix)
            if p.exists():
                p.unlink()
    _write_workspace_storage_meta(storage_dir, folder_uri)
    success("OK")
    info(f"Backup: {backup_db}")


def _require_unlocked_for_merge(dst_db: Path, src_dbs: list[Path]) -> None:
    # * SQLite can keep state in WAL/SHM files; treat them as part of the lock set.
    lock_targets: list[Path] = []
    for db in [dst_db, *src_dbs]:
        lock_targets.append(db)
        lock_targets.append(db.with_name(db.name + "-wal"))
        lock_targets.append(db.with_name(db.name + "-shm"))

    try:
        assert_paths_unlocked(lock_targets)
        return
    except WorkspaceStorageLockedError as exc:
        if not is_interactive():
            raise

        while True:
            choice = prompt_choice(
                "Workspace DB appears locked. Close Cursor and retry?",
                {"r": "Retry lock check", "a": "Abort"},
                default="r",
            )
            if choice == "a":
                raise exc
            try:
                assert_paths_unlocked(lock_targets)
                return
            except WorkspaceStorageLockedError:
                continue

def _cmd_copy_mode_c(
    *,
    cursor_user_dir: Path,
    src: Path,
    dst: Path,
    overwrite_dst: bool | None,
    overwrite_workspace_storage: bool | None,
    merge_workspace_storage: bool,
    unsafe_db: bool,
    assume_yes: bool,
) -> None:
    src = _normalize_workspace_path(src, role="Source", must_exist=True)
    dst_input = _normalize_workspace_path(dst, role="Destination", must_exist=False)
    dst_container, dst = _resolve_destination_folder(src=src, dst_input=dst_input)
    if dst_container != dst and not dst_container.exists():
        dst_container.mkdir(parents=True, exist_ok=True)
    if dst == src:
        raise ValueError("Destination resolves to the same folder as Source. Choose a different destination.")
    info(f"Resolved destination: {dst}")

    src_ws_id = _require_existing_workspace_storage_id(cursor_user_dir, src)
    src_storage_dir = workspace_storage_dir(cursor_user_dir, src_ws_id)
    unsafe_db = _handle_workspace_db_lock_dialog(
        src_storage_dir=src_storage_dir,
        unsafe_db=unsafe_db,
        assume_yes=assume_yes,
    )

    _handle_overwrite_folder_dialog(dst, overwrite_dst=overwrite_dst, assume_yes=assume_yes)

    workspace_copy_stats = copy_tree_with_progress(
        src_dir=src,
        dst_dir=dst,
        desc="Copy workspace",
    )

    dst_ws_id = compute_folder_workspace_id(dst).workspace_id
    dst_storage_dir = workspace_storage_dir(cursor_user_dir, dst_ws_id)
    dst_folder_uri = path_to_folder_uri(dst)
    storage_copy_stats: CopyStats | None = None
    storage_merge_result: MergeResult | None = None
    if dst_storage_dir.exists():
        action = _resolve_existing_workspace_storage_action(
            dst_storage_dir=dst_storage_dir,
            overwrite_workspace_storage=overwrite_workspace_storage,
            merge_workspace_storage=merge_workspace_storage,
            assume_yes=assume_yes,
        )
        if action == "merge":
            storage_merge_result = _merge_workspace_storage_db(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
            )
            _write_workspace_storage_meta(dst_storage_dir, dst_folder_uri)
        else:
            storage_copy_stats = _clone_workspace_storage(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
                dst_folder_uri=dst_folder_uri,
                overwrite=True,
                assume_yes=assume_yes,
            )
    else:
        storage_copy_stats = _clone_workspace_storage(
            src_storage_dir=src_storage_dir,
            dst_storage_dir=dst_storage_dir,
            dst_folder_uri=dst_folder_uri,
            overwrite=overwrite_workspace_storage,
            assume_yes=assume_yes,
        )

    success("OK")
    info(f"Copied workspace: {src} -> {dst}")
    if storage_merge_result is not None:
        info(f"Merged workspaceStorage DB: {src_ws_id} -> {dst_ws_id}")
        info(
            "Inserted keys: ItemTable="
            + str(storage_merge_result.inserted_itemtable_keys)
            + " cursorDiskKV="
            + str(storage_merge_result.inserted_cursordiskkv_keys)
        )
        info(
            f"Composer entries: {storage_merge_result.composer_ids_before} -> "
            f"{storage_merge_result.composer_ids_after}"
        )
        info(f"Backup: {storage_merge_result.backup_path}")
    else:
        info(f"Cloned workspaceStorage: {src_ws_id} -> {dst_ws_id}")
    _print_copy_stats("Workspace files", workspace_copy_stats)
    if storage_copy_stats is not None:
        _print_copy_stats("WorkspaceStorage", storage_copy_stats)


def _cmd_move_mode_c(
    *,
    cursor_user_dir: Path,
    src: Path,
    dst: Path,
    overwrite_dst: bool | None,
    overwrite_workspace_storage: bool | None,
    merge_workspace_storage: bool,
    unsafe_db: bool,
    assume_yes: bool,
) -> None:
    src = _normalize_workspace_path(src, role="Source", must_exist=True)
    dst_input = _normalize_workspace_path(dst, role="Destination", must_exist=False)
    dst_container, dst = _resolve_destination_folder(src=src, dst_input=dst_input)
    if dst_container != dst and not dst_container.exists():
        dst_container.mkdir(parents=True, exist_ok=True)
    if dst == src:
        raise ValueError("Destination resolves to the same folder as Source. Choose a different destination.")
    info(f"Resolved destination: {dst}")

    src_ws_id = _require_existing_workspace_storage_id(cursor_user_dir, src)
    src_storage_dir = workspace_storage_dir(cursor_user_dir, src_ws_id)
    unsafe_db = _handle_workspace_db_lock_dialog(
        src_storage_dir=src_storage_dir,
        unsafe_db=unsafe_db,
        assume_yes=assume_yes,
    )

    _handle_overwrite_folder_dialog(dst, overwrite_dst=overwrite_dst, assume_yes=assume_yes)

    shutil.move(src, dst)

    dst_ws_id = compute_folder_workspace_id(dst).workspace_id
    dst_storage_dir = workspace_storage_dir(cursor_user_dir, dst_ws_id)
    dst_folder_uri = path_to_folder_uri(dst)
    storage_copy_stats: CopyStats | None = None
    storage_merge_result: MergeResult | None = None
    if dst_storage_dir.exists():
        action = _resolve_existing_workspace_storage_action(
            dst_storage_dir=dst_storage_dir,
            overwrite_workspace_storage=overwrite_workspace_storage,
            merge_workspace_storage=merge_workspace_storage,
            assume_yes=assume_yes,
        )
        if action == "merge":
            storage_merge_result = _merge_workspace_storage_db(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
            )
            _write_workspace_storage_meta(dst_storage_dir, dst_folder_uri)
        else:
            storage_copy_stats = _clone_workspace_storage(
                src_storage_dir=src_storage_dir,
                dst_storage_dir=dst_storage_dir,
                dst_folder_uri=dst_folder_uri,
                overwrite=True,
                assume_yes=assume_yes,
            )
    else:
        storage_copy_stats = _clone_workspace_storage(
            src_storage_dir=src_storage_dir,
            dst_storage_dir=dst_storage_dir,
            dst_folder_uri=dst_folder_uri,
            overwrite=overwrite_workspace_storage,
            assume_yes=assume_yes,
        )

    success("OK")
    info(f"Moved workspace: {src} -> {dst}")
    if storage_merge_result is not None:
        info(f"Merged workspaceStorage DB: {src_ws_id} -> {dst_ws_id}")
        info(
            "Inserted keys: ItemTable="
            + str(storage_merge_result.inserted_itemtable_keys)
            + " cursorDiskKV="
            + str(storage_merge_result.inserted_cursordiskkv_keys)
        )
        info(
            f"Composer entries: {storage_merge_result.composer_ids_before} -> "
            f"{storage_merge_result.composer_ids_after}"
        )
        info(f"Backup: {storage_merge_result.backup_path}")
    else:
        info(f"Cloned workspaceStorage: {src_ws_id} -> {dst_ws_id}")
    if storage_copy_stats is not None:
        _print_copy_stats("WorkspaceStorage", storage_copy_stats)


def _require_existing_workspace_storage_id(cursor_user_dir: Path, folder: Path) -> str:
    found = find_workspace_storage_id_for_folder(cursor_user_dir, folder)
    if found:
        return found
    # ! Fallback: compute id (works only if folder stat matches existing id).
    computed = compute_folder_workspace_id(folder).workspace_id
    if workspace_storage_dir(cursor_user_dir, computed).exists():
        return computed
    raise FileNotFoundError(
        "No workspaceStorage entry found for this folder. "
        "Open the folder once in Cursor, then retry."
    )


def _resolve_existing_workspace_storage_action(
    *,
    dst_storage_dir: Path,
    overwrite_workspace_storage: bool | None,
    merge_workspace_storage: bool,
    assume_yes: bool,
) -> str:
    """Resolves how to handle an existing destination workspaceStorage directory."""
    if merge_workspace_storage:
        if overwrite_workspace_storage is not None:
            raise ValueError(
                "Do not combine --merge-workspace-storage with "
                "--overwrite-workspace-storage/--no-overwrite-workspace-storage."
            )
        return "merge"

    if overwrite_workspace_storage is True:
        return "overwrite"

    if overwrite_workspace_storage is False:
        raise FileExistsError(
            f"workspaceStorage exists: {dst_storage_dir}. "
            "Overwriting is disabled. Use --merge-workspace-storage or --overwrite-workspace-storage."
        )

    # * overwrite_workspace_storage is None.
    if assume_yes or not is_interactive():
        raise FileExistsError(
            f"workspaceStorage exists: {dst_storage_dir}. "
            "Specify --merge-workspace-storage or --overwrite-workspace-storage."
        )

    choice = prompt_choice(
        "Destination workspaceStorage already exists. What next?",
        {
            "m": "Merge source chats into existing destination (recommended)",
            "o": "Overwrite destination workspaceStorage (delete and replace)",
            "a": "Abort",
        },
        default="m",
    )
    if choice == "m":
        return "merge"
    if choice == "o":
        return "overwrite"
    raise FileExistsError(f"Aborted by user due to existing workspaceStorage: {dst_storage_dir}")


def _write_workspace_storage_meta(storage_dir: Path, folder_uri: str) -> None:
    """Writes/updates workspaceStorage `workspace.json` to match the folder URI."""
    meta = storage_dir / "workspace.json"
    meta.write_text('{\n  "folder": "' + folder_uri + '"\n}', encoding="utf-8")


def _merge_workspace_storage_db(*, src_storage_dir: Path, dst_storage_dir: Path) -> MergeResult:
    """Merges workspace DB chat state from src into existing dst."""
    src_db = (src_storage_dir / "state.vscdb").resolve()
    dst_db = (dst_storage_dir / "state.vscdb").resolve()
    if not src_db.exists():
        raise FileNotFoundError(src_db)
    if not dst_db.exists():
        raise FileNotFoundError(dst_db)

    # * Merging writes and swaps the destination DB file; it must be unlocked.
    _require_unlocked_for_merge(dst_db, [src_db])
    return merge_workspace_state(dst_db_path=dst_db, src_db_paths=[src_db])


def _clone_workspace_storage(
    *,
    src_storage_dir: Path,
    dst_storage_dir: Path,
    dst_folder_uri: str,
    overwrite: bool | None,
    assume_yes: bool,
) -> CopyStats:
    _handle_overwrite_folder_dialog(
        dst_storage_dir, overwrite_dst=overwrite, assume_yes=assume_yes, label="workspaceStorage"
    )

    stats = copy_tree_with_progress(
        src_dir=src_storage_dir,
        dst_dir=dst_storage_dir,
        desc="Copy workspaceStorage",
    )
    _write_workspace_storage_meta(dst_storage_dir, dst_folder_uri)
    return stats


def _print_copy_stats(label: str, stats: CopyStats) -> None:
    mib = stats.bytes_copied / (1024 * 1024)
    mib_s = stats.bytes_per_second / (1024 * 1024)
    info(f"{label}: files={stats.files_copied}, dirs={stats.dirs_created}, bytes={mib:.2f} MiB")
    info(f"{label}: time={stats.duration_s:.2f}s, speed={mib_s:.2f} MiB/s")


def _handle_overwrite_folder_dialog(
    path: Path,
    *,
    overwrite_dst: bool | None,
    assume_yes: bool,
    label: str = "destination",
) -> None:
    if not path.exists():
        return

    if overwrite_dst is False:
        raise FileExistsError(f"{label} exists: {path}. Overwrite disabled.")

    if overwrite_dst is None:
        if assume_yes or not is_interactive():
            raise FileExistsError(
                f"{label} exists: {path}. Use --overwrite-dst/--overwrite-workspace-storage to overwrite."
            )
        if not prompt_yes_no(f"{label} exists: {path}. Overwrite (delete) it?", default=False):
            raise FileExistsError(f"{label} overwrite rejected by user: {path}")

    while True:
        try:
            _robust_rmtree(path)
            return
        except OSError as exc:
            if assume_yes or not is_interactive():
                raise
            print()
            print(f"Failed to delete {label}: {path}")
            print(str(exc))
            print()
            if prompt_choice(
                "What next?",
                {"r": "Retry delete", "a": "Abort"},
                default="r",
            ) == "r":
                time.sleep(0.25)
                continue
            raise PermissionError(f"Aborted by user due to delete failure: {path}") from exc

def _robust_rmtree(path: Path, *, retries: int = 5, delay_s: float = 0.15) -> None:
    """Removes a directory tree, handling Windows readonly files."""
    last_exc: OSError | None = None
    for attempt in range(retries):
        try:
            _rmtree_once(path)
            return
        except OSError as exc:
            last_exc = exc
            if not _is_transient_delete_error(exc):
                raise
            time.sleep(delay_s * (attempt + 1))
    if last_exc is not None:
        raise last_exc


def _rmtree_once(path: Path) -> None:
    def _handle_exc(func, target_path: str, exc: BaseException) -> None:
        if isinstance(exc, FileNotFoundError):
            return
        if isinstance(exc, PermissionError):
            try:
                os.chmod(target_path, stat.S_IWRITE)
            except OSError:
                pass
            try:
                func(target_path)
                return
            except OSError:
                pass
        raise exc

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, ignore_errors=False, onexc=_handle_exc)
        return

    def _onerror(func, target_path: str, exc_info) -> None:  # pragma: no cover
        _handle_exc(func, target_path, exc_info[1])

    shutil.rmtree(path, ignore_errors=False, onerror=_onerror)  # pragma: no cover


def _is_transient_delete_error(exc: OSError) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if os.name == "nt":
        winerror = getattr(exc, "winerror", None)
        return winerror in (5, 32, 33)
    return False


def _handle_workspace_db_lock_dialog(
    *,
    src_storage_dir: Path,
    unsafe_db: bool,
    assume_yes: bool,
) -> bool:
    if unsafe_db:
        return True

    db_paths = list(workspace_db_paths(src_storage_dir))
    if is_interactive():
        info("Checking workspace DB lock...")
    try:
        assert_paths_unlocked(db_paths)
        if is_interactive():
            success("LOCK CHECK: OK")
        return False
    except WorkspaceStorageLockedError as exc:
        if assume_yes:
            # * In auto-confirm mode, we do not continue unsafely without explicit flag.
            raise exc
        if not is_interactive():
            raise exc

        while True:
            warn(str(exc))
            choice = prompt_choice(
                "Workspace DB is locked. What next?",
                {
                    "r": "Retry lock check (after closing Cursor)",
                    "u": "Continue with -UnsafeDB (may copy inconsistent state)",
                    "a": "Abort",
                },
                default="r",
            )
            if choice == "r":
                time.sleep(0.25)
                try:
                    assert_paths_unlocked(db_paths)
                    success("LOCK CHECK: OK")
                    return False
                except WorkspaceStorageLockedError as retry_exc:
                    exc = retry_exc
                    continue
            if choice == "u":
                if prompt_yes_no("Proceed with UnsafeDB?", default=False):
                    return True
                continue
            raise WorkspaceStorageLockedError("Aborted by user due to locked workspace DB.")


def _tui_config_to_argv(cfg) -> list[str]:
    argv: list[str] = []
    if cfg.cursor_user_dir is not None:
        argv += ["--cursor-user-dir", str(cfg.cursor_user_dir)]

    argv.append(cfg.cmd)

    if cfg.cmd == "doctor":
        if cfg.doctor_all:
            argv.append("--all")
            if cfg.doctor_fix_all:
                argv.append("--fix-all")
            if cfg.doctor_delete_legacy:
                argv.append("--delete-legacy")
            if not cfg.doctor_check_payloads:
                argv.append("--no-check-payloads")
            if cfg.assume_yes:
                argv.append("--yes")
            return argv

        argv += ["--path", str(cfg.src)]
        if not cfg.doctor_check_payloads:
            argv.append("--no-check-payloads")
        return argv

    if cfg.cmd == "merge":
        argv += ["--path", str(cfg.src)]
        if cfg.assume_yes:
            argv.append("--yes")
        if cfg.delete_sources:
            argv.append("--delete-sources")
        return argv

    argv += ["--src", str(cfg.src), "--dst", str(cfg.dst)]
    argv.append("--overwrite-dst" if cfg.overwrite_dst else "--no-overwrite-dst")
    if cfg.merge_workspace_storage:
        argv.append("--merge-workspace-storage")
    else:
        argv.append(
            "--overwrite-workspace-storage"
            if cfg.overwrite_workspace_storage
            else "--no-overwrite-workspace-storage"
        )
    if cfg.unsafe_db:
        argv.append("-UnsafeDB")
    return argv


def _normalize_workspace_path(path: Path, *, role: str, must_exist: bool) -> Path:
    raw = str(path).strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("\"", "'"):
        raw = raw[1:-1].strip()
    path = Path(raw).expanduser().resolve()
    if must_exist and not path.exists():
        raise FileNotFoundError(f"{role} path does not exist: {path}")

    if path.exists() and path.is_file():
        if not is_interactive():
            raise NotADirectoryError(f"{role} must be a folder, but is a file: {path}")
        if prompt_yes_no(
            f"{role} is a file: {path}. Use its parent folder instead?",
            default=True,
        ):
            return path.parent.resolve()
        raise NotADirectoryError(f"{role} must be a folder: {path}")

    if must_exist and not path.is_dir():
        raise NotADirectoryError(f"{role} must be a folder: {path}")

    return path


def _resolve_destination_folder(*, src: Path, dst_input: Path) -> tuple[Path, Path]:
    """Resolves destination folder semantics.

    Rules:
      - If dst name differs from src name, dst is treated as a *container* and we
        create/use dst/src_name.
      - If dst name equals src name, dst is treated as the final folder.
    """
    src_name = src.name
    if not dst_input.name or dst_input.name != src_name:
        return dst_input, dst_input / src_name
    return dst_input.parent, dst_input

