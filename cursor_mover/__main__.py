"""Module entrypoint for `python -m cursor_mover`."""

from __future__ import annotations

import sys

from cursor_mover.bootstrap import bootstrap_and_run


if __name__ == "__main__":
    raise SystemExit(bootstrap_and_run(sys.argv[1:]))

