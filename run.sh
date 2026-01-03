#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="${repo_root}/.venv"
requirements="${repo_root}/requirements.txt"

if [[ -x "${venv_dir}/bin/python" ]]; then
  py="${venv_dir}/bin/python"
elif [[ -x "${venv_dir}/Scripts/python.exe" ]]; then
  # * Git Bash / MSYS on Windows.
  py="${venv_dir}/Scripts/python.exe"
else
  echo "Creating venv: ${venv_dir}"
  python3 -m venv "${venv_dir}"
  py="${venv_dir}/bin/python"
fi

if [[ -f "${requirements}" ]]; then
  echo "Installing dependencies (requirements.txt)..."
  "${py}" -m pip --disable-pip-version-check --quiet install --progress-bar off -r "${requirements}"
else
  echo "Installing dependencies (pyproject.toml)..."
  "${py}" -m pip --disable-pip-version-check --quiet install --progress-bar off -e "${repo_root}"
fi

exec "${py}" -m cursor_mover "$@"

