facade_cpp := "crates/idakit-sys/facade/*.cpp"
facade_sources := "crates/idakit-sys/facade/*.cpp crates/idakit-sys/facade/*.h"

default:
    @just --list

# One-stop gate mirroring CI: a clean run here means CI will very likely pass.
check: fmt-check actionlint clippy tidy test

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
    #!/usr/bin/env bash
    set -euo pipefail
    IDAKIT_EMIT_COMPILE_COMMANDS=1 cargo build -q -p idakit-sys
    # clang-tidy replays compile_commands.json, which records only the flags cc passes -- not
    # the clang driver's implicit macOS -isysroot. Without it clang-tidy can't find the SDK's
    # system headers (stdlib.h), and the broken parse then misfires other checks, so supply it.
    if [ "$(uname -s)" = Darwin ]; then
      clang-tidy -p crates/idakit-sys --extra-arg=-isysroot --extra-arg="$(xcrun --show-sdk-path)" {{ facade_cpp }}
    else
      clang-tidy -p crates/idakit-sys {{ facade_cpp }}
    fi

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Lint the GitHub Actions workflows (auto-discovers .github/workflows/).
actionlint:
    actionlint

# Build the fixture database (gcc a sample, auto-analyze it into an .i64) and run the whole
# suite against it. The kernel-touching integration tests skip without IDAKIT_TEST_DB.
ci-test:
    #!/usr/bin/env bash
    set -euo pipefail
    work="$(mktemp -d)"
    # On Windows this recipe runs under git-bash but cargo/clang are native; a mixed C:/-style
    # path is understood by both, so the fixture and DB paths agree across the boundary.
    case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) work="$(cygpath -m "$work")" ;; esac
    # Force an x86-64 fixture even on an arm64 host, so the suite runs against an identical
    # target everywhere: arm64 Linux cross-compiles, macOS builds the x86-64 slice, and Windows'
    # clang defaults to the x86_64-pc-windows-msvc target.
    case "$(uname -s)" in
      Darwin) cc=(clang -arch x86_64) ;;
      MINGW*|MSYS*|CYGWIN*) cc=(clang) ;;
      *) if [ "$(uname -m)" = x86_64 ]; then cc=(gcc); else cc=(x86_64-linux-gnu-gcc); fi ;;
    esac
    "${cc[@]}" -O1 -g -o "$work/sample" crates/idakit/tests/fixtures/sample.c
    cargo run -q -p idakit --example make_fixture -- "$work/sample"
    test -f "$work/sample.i64" || { echo "make_fixture produced no .i64" >&2; exit 1; }
    IDAKIT_TEST_DB="$work/sample.i64" cargo nextest run --workspace --no-fail-fast
    cargo test --workspace --doc
