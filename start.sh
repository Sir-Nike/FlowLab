#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/flowlab ]]; then
  if ! command -v uv >/dev/null 2>&1; then
    echo 'Install uv from https://docs.astral.sh/uv/getting-started/installation/ and run this script again.' >&2
    exit 1
  fi
  uv venv --python 3.12 .venv
  uv pip install --python .venv/bin/python -e '.[dev]'
  uv pip install --python .venv/bin/python torch --index-url https://download.pytorch.org/whl/cpu
  uv pip install --python .venv/bin/python tabm
fi
if [[ "${1:-}" == '--setup' ]]; then
  shift
  .venv/bin/flowlab setup --download
elif ! compgen -G 'models/*.json' >/dev/null; then
  .venv/bin/flowlab setup
fi
.venv/bin/python scripts/start_lab.py
exec .venv/bin/flowlab serve "$@"
