#!/bin/sh
# Install the pinned release locally; never compile or install system-wide.
set -eu

version=1.7.7
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)
        arch=amd64
        checksum=023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757
        ;;
    Linux/aarch64|Linux/arm64)
        arch=arm64
        checksum=401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0
        ;;
    *)
        echo 'actionlint setup supports Linux x86_64 and arm64 only.' >&2
        exit 1
        ;;
esac

mkdir -p .tools/bin
temp_dir=$(mktemp -d .tools/actionlint.XXXXXX)
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
archive="actionlint_${version}_linux_${arch}.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
    "https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}" \
    --output "$temp_dir/$archive"
printf '%s  %s\n' "$checksum" "$temp_dir/$archive" | sha256sum --check --status
tar -xzf "$temp_dir/$archive" -C "$temp_dir" actionlint
chmod 755 "$temp_dir/actionlint"
mv -f "$temp_dir/actionlint" .tools/bin/actionlint
