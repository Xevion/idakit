facade_cpp := "crates/idakit-sys/facade/*.cpp"
facade_sources := "crates/idakit-sys/facade/*.cpp crates/idakit-sys/facade/*.h"

default:
    @just --list

# One-stop gate mirroring CI: a clean run here means CI will very likely pass.
check: fmt-check actionlint clippy tidy (doc "hermetic") test

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

# Build API docs, warnings-as-errors (broken links, bad code blocks, bare URLs all fail).
# Default scrapes example call-sites onto each item (nightly + real runtime); `hermetic`
# skips scraping and builds under DOCS_RS, so no IDA runtime -- CI and `check` use it.
doc mode="scrape":
    RUSTDOCFLAGS="-D warnings" {{ if mode == "hermetic" { "DOCS_RS=1 cargo doc --workspace --no-deps" } else { "cargo +nightly doc --workspace --no-deps -Z rustdoc-scrape-examples" } }}

# Lint the GitHub Actions workflows (auto-discovers .github/workflows/).
actionlint:
    actionlint

# Like `test`, but --no-fail-fast so one run surfaces every platform's failures. In CI the
# fetch-corpus step exports IDAKIT_CORPUS_MANIFEST, so the dedicated tests source the same
# host-independent canonical fixture the corpus matrix uses.
ci-test:
    cargo nextest run --workspace --no-fail-fast
    cargo test --workspace --doc
