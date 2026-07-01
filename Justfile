facade_cpp := "crates/idakit-sys/facade/*.cpp"
facade_sources := "crates/idakit-sys/facade/*.cpp crates/idakit-sys/facade/*.h"

default:
    @just --list

check:
    cargo check --workspace

build:
    cargo build --workspace

test:
    cargo test --workspace

fmt: fmt-rust fmt-cpp

fmt-rust:
    cargo fmt --all

fmt-cpp:
    clang-format -i {{ facade_sources }}

fmt-cpp-check:
    clang-format --dry-run --Werror {{ facade_sources }}

tidy:
    IDAKIT_EMIT_COMPILE_COMMANDS=1 cargo build -q -p idakit-sys
    clang-tidy -p crates/idakit-sys {{ facade_cpp }}

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Build the workspace, then run the end-to-end suite against a freshly built fixture
# database (gcc a sample, auto-analyze it, roundtrip over it). Needs the IDA runtime.
ci-test:
    #!/usr/bin/env bash
    set -euo pipefail
    # roundtrip and ctor are harness = false (own fn main), which nextest can't list or
    # drive -- exclude both and run them below via cargo test. --doc keeps doctests nextest
    # doesn't cover.
    cargo nextest run --workspace --no-fail-fast -E 'not (binary(roundtrip) or binary(ctor))'
    cargo test --workspace --doc
    cargo test -p idakit --test ctor
    work="$(mktemp -d)"
    gcc -O1 -g -o "$work/sample" crates/idakit/tests/fixtures/sample.c
    cargo run -q -p idakit --example make_fixture -- "$work/sample"
    test -f "$work/sample.i64" || { echo "make_fixture produced no .i64" >&2; exit 1; }
    IDAKIT_TEST_DB="$work/sample.i64" cargo test -p idakit --test roundtrip -- --nocapture

# Build the CI image from a local IDA install ($IDADIR, default ~/ida-pro-9.3), pruning
# the bundled database and *.bak copies out of the build context first.
ci-image:
    #!/usr/bin/env bash
    set -euo pipefail
    idadir="${IDADIR:-$HOME/ida-pro-9.3}"
    image="${IMAGE:-idakit-ci:latest}"
    [ -f "$idadir/libida.so" ] || { echo "no libida.so under IDADIR=$idadir" >&2; exit 1; }
    stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
    rsync -a --exclude='*.i64' --exclude='*.bak' "$idadir"/ "$stage"/
    DOCKER_BUILDKIT=1 docker build -f .github/docker/Dockerfile --build-context "ida=$stage" -t "$image" .
