#!/bin/sh
set -eu

decoder_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(CDPATH= cd -- "$decoder_dir/../../.." && pwd -P)
home_dir=$(CDPATH= cd -- "$HOME" && pwd -P)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
if [ -d "$cargo_home" ]; then
    cargo_home=$(CDPATH= cd -- "$cargo_home" && pwd -P)
fi
toolchain_dir=$(rustc --print sysroot)
cd "$decoder_dir"

# Encoded flags keep paths with spaces as one rustc argument. Append remapping
# after inherited flags so this build owns the final path mappings.
separator=$(printf '\037')
encoded_flags=${CARGO_ENCODED_RUSTFLAGS:-}
append_flag() {
    if [ -n "$encoded_flags" ]; then
        encoded_flags="$encoded_flags$separator$1"
    else
        encoded_flags=$1
    fi
}
# Match Cargo's existing encoded-flags precedence. Plain flags are split on
# whitespace only, without glob expansion or evaluation of shell syntax.
if [ "${CARGO_ENCODED_RUSTFLAGS+x}" != x ]; then
    set -f
    for inherited_flag in ${RUSTFLAGS:-}; do
        append_flag "$inherited_flag"
    done
fi
append_flag "--remap-path-prefix=$HOME=/build"
if [ "$home_dir" != "$HOME" ]; then
    append_flag "--remap-path-prefix=$home_dir=/build"
fi
append_flag "--remap-path-prefix=$repo_dir=/blockzilla"
append_flag "--remap-path-prefix=$cargo_home=/cargo"
append_flag "--remap-path-prefix=$toolchain_dir=/rust"
export CARGO_ENCODED_RUSTFLAGS=$encoded_flags
unset RUSTFLAGS
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
artifact="${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/blockzilla_stream_decoder.wasm"

publish() {
    for prefix in "$HOME" "$home_dir" "$repo_dir" "$cargo_home" "$toolchain_dir"; do
        if LC_ALL=C grep -aFq -- "$prefix" "$artifact"; then
            printf '%s\n' 'Refusing to copy a Wasm file with a build-machine path.' >&2
            exit 1
        fi
    done
    if LC_ALL=C grep -aEq '/(Users|home)/' "$artifact"; then
        printf '%s\n' 'Refusing to copy a Wasm file with a build-machine path.' >&2
        exit 1
    fi
    cp "$artifact" "$1"
}

cargo build --locked --release --target wasm32-unknown-unknown --no-default-features
publish ../client/decoder.wasm
cargo build --locked --release --target wasm32-unknown-unknown --no-default-features --features banks
publish ../client/decoder-banks-v2.wasm
cargo build --locked --release --target wasm32-unknown-unknown --no-default-features --features consensus
publish ../client/decoder-consensus-v1.wasm
