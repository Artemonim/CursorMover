# Frequently Asked Questions (FAQ)

## General Questions

### What is CursorMover?

CursorMover is a utility that allows you to move or copy Cursor IDE workspace folders while preserving the Agent chat history. Without this tool, moving a workspace to a different path would cause all chat history to "disappear" from the UI.

### Is it safe to use?

CursorMover includes several safety mechanisms:
- Database lock checking before operations
- Automatic backups before modifying databases
- SQLite integrity checks after modifications
- Read-only diagnostic commands

However, we always recommend making manual backups of your important workspaces before using the tool.

### Which Cursor versions are supported?

CursorMover is designed to work with Cursor IDE 2.3.21+. However, Cursor's internal storage format may change in future versions. The tool attempts to handle these changes gracefully, but it's a best-effort utility.

### Does it work on all operating systems?

Yes! CursorMover supports:
- Windows 10/11
- macOS
- Linux (Ubuntu, Debian, Fedora, etc.)

## Usage Questions

### Do I need to close Cursor before using CursorMover?

Yes, it's strongly recommended to close Cursor (or at least the workspace being operated on) before running CursorMover. This prevents database lock issues and ensures data consistency.

### What's the difference between `copy` and `move`?

- **copy**: Creates a copy of your workspace folder at a new location and duplicates the chat history. The original workspace remains unchanged.
- **move**: Moves your workspace folder to a new location and transfers the chat history. The original workspace is deleted.

### What does the `doctor` command do?

The `doctor` command is a diagnostic tool that shows:
- How Cursor maps your workspace folder to its storage ID
- The folder URI used internally
- Whether the database is locked
- If there are duplicate storage entries

It's a read-only command that doesn't modify anything.

### When should I use the `merge` command?

Use `merge` when you have multiple `workspaceStorage` entries pointing to the same folder URI. This can happen after:
- Restoring backups
- Filesystem metadata changes
- Manual copying of Cursor user data

This is an advanced command for consolidating duplicate entries.

### What does `--merge-workspace-storage` do?

When you use `copy` or `move` to a location that already has workspace storage in Cursor (e.g., you already opened that folder and created chats there), the `--merge-workspace-storage` flag tells CursorMover to merge both chat histories instead of overwriting the destination.

### Can I automate CursorMover with scripts?

Yes! CursorMover provides full CLI support. You can use it in scripts by providing all necessary arguments:

```bash
cursor-mover copy --src "/path/to/source" --dst "/path/to/dest"
```

## Troubleshooting

### "Database is locked" error

This means Cursor is still running or the database files are in use. Solutions:
1. Close Cursor completely
2. Wait a few seconds for files to be released
3. Check if any Cursor processes are still running
4. Restart your computer if the problem persists

If you need to proceed despite the lock (not recommended), use `--unsafe-db`.

### "Workspace not found" error

This means the workspace hasn't been opened in Cursor yet. Solution:
1. Open the folder in Cursor
2. Wait for it to fully load
3. Close Cursor
4. Try CursorMover again

### My chat history is still missing after using CursorMover

Possible causes:
1. Cursor was open during the operation → Close Cursor and reopen
2. The workspace storage ID calculation changed → Check with `doctor` command
3. The operation encountered an error → Check the console output for errors
4. Database corruption → Restore from the `.premerge-*` backup if available

### The tool is very slow

Large databases or many files can take time to process. This is normal. Progress bars are shown for long operations.

### I got an error about Python version

CursorMover requires Python 3.11 or higher. Update your Python installation:
- Windows: Download from [python.org](https://www.python.org/downloads/)
- macOS: Use Homebrew: `brew install python3`
- Linux: Use your package manager: `apt install python3` or `yum install python3`

## Advanced Questions

### How is the workspace ID calculated?

On Windows, Cursor calculates the workspace ID as `md5(fsPath + birthtimeMs)` where:
- `fsPath` is the canonical absolute path
- `birthtimeMs` is the folder's creation timestamp in milliseconds

On macOS/Linux, the calculation is similar but uses different filesystem metadata.

### Can I manually edit the workspace storage?

While technically possible, it's not recommended. Use CursorMover's `merge` command instead, which properly handles:
- Database integrity
- Backup creation
- Transaction safety
- Validation checks

### What happens if CursorMover crashes during an operation?

CursorMover creates backups before modifying databases. Look for files like:
- `state.vscdb.premerge-TIMESTAMP`

You can manually restore these backups by renaming them back to `state.vscdb`.

### Does CursorMover modify my source code files?

No! CursorMover only operates on:
1. The workspace folder structure (copy/move operations)
2. Cursor's `workspaceStorage` metadata and chat databases
3. No source code or project files are modified

### Can I use CursorMover with multi-root workspaces?

Currently, CursorMover only supports single-folder workspaces, not multi-root `.code-workspace` files. This is a limitation of the current implementation.

## Still Have Questions?

If your question isn't answered here:
1. Check the [README.md](README.md) for detailed documentation
2. Search [existing issues](https://github.com/Artemonim/CursorMover/issues)
3. Open a [new issue](https://github.com/Artemonim/CursorMover/issues/new/choose)
