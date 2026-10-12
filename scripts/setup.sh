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
case "$mode" in setup|deps|deps-ci) ;; *) fail 'use setup, deps or deps-ci.' ;; esac
[ "$#" -le 1 ] || fail 'unexpected setup arguments.'
noninteractive=false
if [ "$mode" = deps-ci ]; then
    noninteractive=true
    mode=deps
fi

for tool in sh make cat curl tar gzip sha256sum uname mkdir mktemp chmod mv rm head ssh ssh-keygen ssh-keyscan scp sftp; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing $tool; install this system prerequisite and retry."
done
# Plan before creating tool directories, downloading or synchronizing packages.
ready=false
if [ -x .venv/bin/python ] && [ -x .tools/bin/uv ] && [ -x .tools/bin/actionlint ]; then
    if .venv/bin/python scripts/setup-ready.py &&
       uv_version=$(.tools/bin/uv --version) &&
       { case "$uv_version" in "uv 0.12.23"|"uv 0.12.23 ("*")") true ;; *) false ;; esac; } &&
       [ "$(.tools/bin/actionlint -version)" = 1.7.7 ]; then
        ready=true
    fi
fi
inventory=${INVENTORY:-inventories/production.yml}
if [ "$ready" = true ] && { [ "$mode" = deps ] || [ -e "$inventory" ]; }; then
    echo 'Local tooling/inventory already prepared; no changes required.'
    exit 0
fi
plan_snapshot=$(sha256sum requirements-dev.txt collections.yml scripts/setup.sh scripts/setup-ready.py scripts/install-uv.sh scripts/install-actionlint.sh)
echo 'Plan:'
if [ "$ready" != true ]; then
    echo '  - Download checksum-verified pinned uv/actionlint if absent into .tools/bin.'
    echo '  - Install managed Python 3.12 if absent in .tools/python; create .venv if absent.'
    echo '  - Synchronize the following pinned Python tools and Ansible collections from registries:'
    cat requirements-dev.txt collections.yml
    echo '  - Write project-local .cache/uv and .ansible; network access required.'
fi
if [ "$mode" = setup ] && [ ! -e "$inventory" ]; then
    echo "  - Exclusively create missing inventory at $inventory (0600) and missing parent directories."
fi
echo '  - Rights: current controller user only; no sudo or system package changes.'
if [ "$noninteractive" = true ]; then
    echo 'Noninteractive dependency-only installation authorized by deps-ci.'
else
    printf 'Apply this plan? [y/N] '
    IFS= read -r answer || fail 'plan declined (end of input); no changes requested.'
    case "$answer" in y|Y|yes|YES) ;; *) fail 'plan declined; no changes requested.' ;; esac
fi
[ "$plan_snapshot" = "$(sha256sum requirements-dev.txt collections.yml scripts/setup.sh scripts/setup-ready.py scripts/install-uv.sh scripts/install-actionlint.sh)" ] || fail 'plan inputs changed; STOP.'
umask 077
export ANSIBLE_HOME="$project_dir/.ansible"
export UV_PYTHON_INSTALL_DIR="$project_dir/.tools/python"
export UV_CACHE_DIR="$project_dir/.cache/uv"
# Ignore activated environments and user-level uv configuration; never modify PATH.
unset VIRTUAL_ENV
if [ "$ready" != true ]; then
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
.venv/bin/ansible-galaxy collection install -r collections.yml -p .ansible/collections
sh scripts/install-actionlint.sh
fi

if [ "$mode" = setup ]; then
    .venv/bin/python scripts/access.py setup --inventory "${INVENTORY:-inventories/production.yml}"
fi
