facade_cpp := "crates/idakit-sys/facade/*.cpp"
facade_sources := "crates/idakit-sys/facade/*.cpp crates/idakit-sys/facade/*.h"

default:
    @just --list

# One-stop gate mirroring CI: a clean run here means CI will very likely pass.
check: fmt-check clippy tidy test

build:
    cargo build --workspace

# nextest runs the suite; the kernel-touching integration tests are serialized by
# .config/nextest.toml and skip without their preconditions. Doctests run separately --
# nextest doesn't cover them.
test:
    cargo nextest run --workspace
    cargo test --workspace --doc

fmt: fmt-rust fmt-cpp

fmt-rust:
    cargo fmt --all

fmt-cpp:
    clang-format -i {{ facade_sources }}

fmt-check: fmt-rust-check fmt-cpp-check

fmt-rust-check:
    cargo fmt --all --check

fmt-cpp-check:
    clang-format --dry-run --Werror {{ facade_sources }}

tidy:
    IDAKIT_EMIT_COMPILE_COMMANDS=1 cargo build -q -p idakit-sys
    clang-tidy -p crates/idakit-sys {{ facade_cpp }}

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Build the fixture database (gcc a sample, auto-analyze it into an .i64) and run the whole
# suite against it. The kernel-touching integration tests skip without IDAKIT_TEST_DB.
ci-test:
    #!/usr/bin/env bash
    set -euo pipefail
    work="$(mktemp -d)"
    gcc -O1 -g -o "$work/sample" crates/idakit/tests/fixtures/sample.c
    cargo run -q -p idakit --example make_fixture -- "$work/sample"
    test -f "$work/sample.i64" || { echo "make_fixture produced no .i64" >&2; exit 1; }
    IDAKIT_TEST_DB="$work/sample.i64" cargo nextest run --workspace --no-fail-fast
    cargo test --workspace --doc

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
