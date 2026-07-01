default:
    @just --list

check:
    cargo check --workspace

build:
    cargo build --workspace

test:
    cargo test --workspace

fmt:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets

# Build the workspace, then run the end-to-end suite against a freshly built fixture
# database (gcc a sample, auto-analyze it, roundtrip over it). Needs the IDA runtime.
ci-test:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo test --workspace --no-fail-fast
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
