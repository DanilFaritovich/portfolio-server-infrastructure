#!/bin/sh
# The only dependency/toolchain setup path. Does not access managed hosts.
set -eu

fail() {
    echo "Setup: $*" >&2
    exit 1
}

project_dir=$(CDPATH= cd "${0%/*}/.." && pwd)
cd "$project_dir"
mode=${1:-setup}
case "$mode" in setup|deps) ;; *) fail 'use setup or deps.' ;; esac

for tool in sh make curl tar gzip sha256sum uname mkdir mktemp chmod mv rm head ssh ssh-keygen ssh-keyscan scp sftp; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing $tool; install this system prerequisite and retry."
done
umask 077
export ANSIBLE_HOME="$project_dir/.ansible"
export UV_PYTHON_INSTALL_DIR="$project_dir/.tools/python"
export UV_CACHE_DIR="$project_dir/.cache/uv"
# Ignore activated environments and user-level uv configuration; never modify PATH.
unset VIRTUAL_ENV
sh scripts/install-uv.sh
uv="$project_dir/.tools/bin/uv"

# --system ignores any existing virtualenv; --managed-python excludes system Python.
if ! runtime=$("$uv" --no-config python find --system --managed-python --no-python-downloads 3.12 2>/dev/null); then
    "$uv" --no-config python install 3.12 --no-bin
    runtime=$("$uv" --no-config python find --system --managed-python --no-python-downloads 3.12)
fi
case "$runtime" in "$UV_PYTHON_INSTALL_DIR"/*) ;; *) fail 'uv returned a Python outside project-local tooling.' ;; esac
[ -x "$runtime" ] || fail 'managed Python is not executable.'
"$runtime" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))' || fail 'managed Python must be 3.12.'

if [ -e .venv ]; then
    [ -x .venv/bin/python ] || fail 'existing .venv is incomplete; inspect it before retrying.'
    .venv/bin/python -c 'import sys; from pathlib import Path; sys.exit(not (sys.version_info[:2] == (3, 12) and Path(sys.base_prefix).resolve().is_relative_to(Path(".tools/python").resolve())))' \
        || fail 'existing .venv must use project-managed Python 3.12; inspect it before retrying.'
else
    "$uv" --no-config venv --python "$runtime" .venv
fi
"$uv" --no-config pip install --python "$project_dir/.venv/bin/python" -r requirements-dev.txt
.venv/bin/ansible-galaxy collection install -r requirements.yml -p .ansible/collections
sh scripts/install-actionlint.sh

if [ "$mode" = setup ]; then
    .venv/bin/python scripts/access.py setup --inventory "${INVENTORY:-inventories/production.yml}"
fi
