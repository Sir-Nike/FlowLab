#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -f token ]]; then
  umask 077
  ../.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))' > token
fi
if [[ ! -f scapy-vendor.tar.gz ]]; then
  ../.venv/bin/python - <<'PY'
from pathlib import Path
import scapy, tarfile
with tarfile.open('scapy-vendor.tar.gz', 'w:gz') as archive:
    archive.add(Path(scapy.__file__).parent, arcname='scapy',
                filter=lambda item: None if '__pycache__' in item.name or item.name.endswith('.pyc') else item)
PY
fi
if ! command -v vagrant >/dev/null; then echo 'Install Vagrant and vagrant-libvirt as described in README.md'; exit 1; fi
vagrant up --provider=libvirt
