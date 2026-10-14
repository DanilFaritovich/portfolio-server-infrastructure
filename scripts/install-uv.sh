#!/bin/sh
# Verified, pinned prebuilt uv; no installer execution or global installation.
set -eu

version=0.12.23
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)
        target=x86_64-unknown-linux-gnu
        checksum=9167d72b3319674b6303c4cbe071854bba13ebdf3d76b1a7cbdc175471fb66d6
        ;;
    Linux/aarch64|Linux/arm64)
        target=aarch64-unknown-linux-gnu
        checksum=6524bd338177ed50d035d39354e12545e993bbeba2ecbddf0480c5b3a81d313f
        ;;
    *)
        echo 'uv setup supports Linux x86_64 and arm64 only.' >&2
        exit 1
        ;;
esac

if [ -e .tools/bin/uv ]; then
    [ -x .tools/bin/uv ] || { echo 'Existing local uv is not executable.' >&2; exit 1; }
    installed_version=$(.tools/bin/uv --version) || { echo 'Existing local uv version check failed.' >&2; exit 1; }
    case "$installed_version" in
        "uv $version"|"uv $version ("*")") ;;
        *)
        echo "Existing local uv must be version $version; inspect/remove it before retrying." >&2
        exit 1
        ;;
    esac
    exit 0
fi

mkdir -p .tools/bin
temp_dir=$(mktemp -d .tools/uv.XXXXXX)
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
archive="uv-${target}.tar.gz"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    "https://github.com/astral-sh/uv/releases/download/${version}/${archive}" \
    --output "$temp_dir/$archive"
if ! printf '%s  %s\n' "$checksum" "$temp_dir/$archive" | sha256sum --check --status; then
    echo 'uv archive checksum verification failed; stopping before extraction or execution.' >&2
    exit 1
fi
tar -xzf "$temp_dir/$archive" -C "$temp_dir" "uv-${target}/uv"
chmod 755 "$temp_dir/uv-${target}/uv"
downloaded_version=$("$temp_dir/uv-${target}/uv" --version) || { echo 'Verified uv version check failed.' >&2; exit 1; }
case "$downloaded_version" in
    "uv $version"|"uv $version ("*")") ;;
    *)
    echo 'Verified uv archive contains an unexpected version; stopping.' >&2
    exit 1
    ;;
esac
mv "$temp_dir/uv-${target}/uv" .tools/bin/uv
