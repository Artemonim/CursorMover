# CursorMover

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/Artemonim/CursorMover/actions/workflows/tests.yml/badge.svg)](https://github.com/Artemonim/CursorMover/actions/workflows/tests.yml)

A utility to move or copy a project folder (Cursor workspace) **together with the Agent history**, so that after changing the path the history doesn't "disappear" from the UI.

Based on an observation from a Cursor Community thread: [Lost access to 5-7 Agent conversations after workspace folder restructure](https://forum.cursor.com/t/lost-access-to-5-7-agent-conversations-after-workspace-folder-restructure/147837).

## Features

- ✅ **Copy/Move workspaces** with full chat history preservation
- ✅ **Merge chat histories** from duplicate workspace storage entries
- ✅ **Database lock checking** for safe operations
- ✅ **Cross-platform support** (Windows, macOS, Linux)
- ✅ **Interactive TUI** for easy usage
- ✅ **CLI mode** for scripting and automation
- ✅ **Workspace diagnostics** (doctor command)
- ✅ **Automatic backup** before risky operations
- ✅ **SQLite integrity checks** after modifications

## Table of Contents

- [Important (Data Safety)](#important-data-safety)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [What exactly happens (Mode C)](#what-exactly-happens-mode-c)
- [Commands](#commands)
  - [Doctor](#doctor-command)
  - [Copy/Move](#copymove-workspace--transfer-chats)
  - [Merge](#merge-command)
- [CLI overview](#cli-overview)
- [Limitations](#limitations)
- [Tests](#tests)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

Quick install from source:

```bash
git clone https://github.com/Artemonim/CursorMover.git
cd CursorMover
```

## Important (Data Safety)

- **Close Cursor** (or at least close the workspace being operated on) before touching `workspaceStorage`. Otherwise, `state.vscdb` can be locked or inconsistent.
- By default the tool **checks for a lock** on `state.vscdb` (and WAL/SHM files, if present) and **aborts** if the files are busy. You can bypass the lock check with `--unsafe-db` / `-UnsafeDB` (not recommended).
- `copy` / `move` **do not modify** `state.vscdb` contents as SQLite by default: they copy/move folders and clone the entire `workspaceStorage/<id>` directory, updating only `workspace.json` (metadata).
- If the destination `workspaceStorage/<id>` already exists (for example, you opened the new path in Cursor and created new chats there), `copy` / `move` can **merge** source chat state into the existing destination (interactive prompt or `--merge-workspace-storage`). This **does modify** the destination `state.vscdb` (SQLite), runs `PRAGMA integrity_check`, and writes a backup `state.vscdb.premerge-<timestamp>`.
- `merge` **does modify** `state.vscdb` as SQLite (insert/replace only), runs `PRAGMA integrity_check`, and writes a backup `state.vscdb.premerge-<timestamp>` next to the destination DB.
- Still recommended: make a manual backup of the entire `workspaceStorage/<id>` folder before experimenting.

## What exactly happens (Mode C)

Cursor stores workspace data in:

- `Cursor/User/workspaceStorage/<WORKSPACE_ID>/state.vscdb`
- `Cursor/User/workspaceStorage/<WORKSPACE_ID>/workspace.json`

Where `<WORKSPACE_ID>` is calculated from the path + file system metadata. On Windows, this is effectively `md5(fsPath + birthtimeMs)` (see `cursor_mover/workspace_id.py`).

Mode **C**:

- copies/moves the project folder;
- calculates the new `<WORKSPACE_ID>` for the new path;
- copies `workspaceStorage/<old_id>` → `workspaceStorage/<new_id>`;
- updates `workspace.json` inside `workspaceStorage/<new_id>` to the new folder URI.

This is the **migration** path: use `copy` / `move` when you change the workspace folder location on disk.

## Merge (command)

In rare cases you may end up with **multiple** `workspaceStorage/<id>` entries that point to the **same folder URI** (for example after restores, metadata changes, or manual copying of Cursor user data). The `merge` command merges chat-related keys from those entries into the current one. Use `--delete-sources` to delete merged source entries after a successful merge.

Note: `merge` is **not** a migration. It does not move/copy your workspace folder and does not change its path. It only consolidates duplicate `workspaceStorage` state for the same folder URI.

## Doctor (command)

`doctor` prints how Cursor maps a workspace folder to `workspaceStorage/<id>`:

- folder URI (`file:///...`) used inside `workspaceStorage/*/workspace.json`;
- workspaceStorage id found by scanning existing `workspace.json`;
- workspaceStorage id computed from the folder path + filesystem metadata (what Cursor uses);
- the exact inputs used for hashing (fsPath + stat salt);
- lock check for `state.vscdb` (+ WAL/SHM if present) when a workspaceStorage entry is found.
- warns if multiple `workspaceStorage/<id>` entries exist for the same folder URI (and suggests `merge`).

This command is read-only (no modifications).

## Quick Start

Simplest run (Windows PowerShell):

```powershell
.\run.ps1
```

Simplest run (macOS/Linux):

```bash
./run.sh
```

Manual venv activation (Windows PowerShell):

```powershell
.venv\Scripts\Activate.ps1
```

Important: when launching via `python -m cursor_mover` / `python main.py` **from a repo checkout**, the utility attempts to automatically use `.venv` and install dependencies from `requirements.txt` (can be disabled via environment variables `CURSOR_MOVER_SKIP_BOOTSTRAP=1` and `CURSOR_MOVER_SKIP_INSTALL=1`).

## CLI overview

Show help:

```powershell
python -m cursor_mover --help
```

Global option:

- `--cursor-user-dir`: override auto-detected Cursor `.../Cursor/User` directory.

Interactive TUI (only when stdin/stdout are TTY):

```powershell
python -m cursor_mover
```

TUI includes `copy`, `move`, `doctor`, and `merge`.

Note: `copy` / `move` / `merge` require that the workspace folder was opened in Cursor at least once (so it has an existing `workspaceStorage/<id>` entry). If not, open the folder in Cursor and retry.

## Limitations

- Folder workspaces only (not multi-root `.code-workspace` files).
- Cursor storage format and workspace ID logic can change between versions; treat this as a best-effort utility.

About `--dst` semantics:

- If `--dst` **does not match** the source folder name (`--src`), then `--dst` is considered a *container* and the actual destination will be `--dst/<src name>`.
- If `--dst` **matches** the source folder name, then the copy/move is performed directly into `--dst`.

Check (doctor):

```powershell
python -m cursor_mover doctor --path "G:\GitHub\RUSTDemo"
```

Copy workspace + transfer chats (Mode C):

```powershell
python -m cursor_mover copy --src "G:\GitHub\RUSTDemo" --dst "T:\Temp\RUSTDemo"
```

Move workspace + transfer chats (Mode C):

```powershell
python -m cursor_mover move --src "G:\GitHub\RUSTDemo" --dst "T:\Temp\RUSTDemo"
```

Copy/move when destination workspaceStorage already exists (preserve destination chats):

```powershell
python -m cursor_mover copy --src "G:\GitHub\RUSTDemo" --dst "T:\Temp\RUSTDemo" --merge-workspace-storage
```

Unsafe copy with locked DB (experimental):

```powershell
python -m cursor_mover copy -UnsafeDB --src "G:\GitHub\RUSTDemo" --dst "T:\Temp\RUSTDemo"
```

Merge chat state from other workspaceStorage entries for the same folder URI (advanced):

```powershell
python -m cursor_mover merge --path "G:\GitHub\RUSTDemo"
```

## Tests

```powershell
python -m unittest -v
```

## Documentation

Comprehensive documentation is available:

- **[Installation Guide](INSTALL.md)** - Detailed installation instructions
- **[Usage Examples](EXAMPLES.md)** - Practical examples and scenarios
- **[FAQ](FAQ.md)** - Frequently asked questions
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project
- **[Publishing Guide](PUBLISHING.md)** - Instructions for maintainers
- **[Security Policy](SECURITY.md)** - Security information and reporting
- **[Changelog](CHANGELOG.md)** - Version history and changes
- **[Roadmap](ROADMAP.md)** - Future plans and ideas
- **[Pre-Release Checklist](PRE_RELEASE_CHECKLIST.md)** - Release preparation checklist

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

### Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes in each version.

## Support

If you encounter any issues or have questions:

1. Check the [existing issues](https://github.com/Artemonim/CursorMover/issues)
2. Read the [documentation](README.md)
3. Open a [new issue](https://github.com/Artemonim/CursorMover/issues/new/choose) if needed

## Acknowledgments

- Inspired by the Cursor Community discussion on workspace migration
- Built with Python and love for the developer community

## Disclaimer

This is a best-effort utility. Cursor's internal storage format and workspace ID logic may change between versions. Always make backups before performing operations on important workspaces.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.