facade_cpp := "crates/idakit-sys/facade/*.cpp"
facade_sources := "crates/idakit-sys/facade/*.cpp crates/idakit-sys/facade/*.h"

default:
    @just --list

# One-stop gate mirroring CI: a clean run here means CI will very likely pass.
check: fmt-check actionlint clippy tidy (doc "hermetic") readme-check test

build:
    cargo build --workspace

# nextest runs the suite; the kernel-touching integration tests are serialized by
# .config/nextest.toml and skip without their preconditions. Doctests run separately --
# nextest doesn't cover them.
test:
    cargo nextest run --workspace --all-features
    cargo test --workspace --all-features --doc

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

# clang-tidy runs one TU at a time; xargs -P fans the facade files across cores so wall time
# tracks the slowest file, not their sum. In CI, CTCACHE_DIR routes through clang-tidy-cache
# (content-hash keyed on compile command + .clang-tidy + source) to skip an untouched facade;
# local runs without it use plain clang-tidy.
tidy:
    #!/usr/bin/env bash
    set -euo pipefail
    IDAKIT_EMIT_COMPILE_COMMANDS=1 cargo build -q -p idakit-sys
    cd crates/idakit-sys
    # clang-tidy replays compile_commands.json, which records only the flags cc passes -- not
    # the clang driver's implicit macOS -isysroot. Without it clang-tidy can't find the SDK's
    # system headers (stdlib.h), and the broken parse then misfires other checks, so supply it.
    extra_args=()
    if [ "$(uname -s)" = Darwin ]; then
      extra_args=(--extra-arg=-isysroot --extra-arg="$(xcrun --show-sdk-path)")
    fi
    tidy_cmd=(clang-tidy)
    if [ -n "${CTCACHE_DIR:-}" ] && command -v clang-tidy-cache >/dev/null 2>&1; then
      tidy_cmd=(clang-tidy-cache "$(command -v clang-tidy)")
    fi
    nproc_val="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
    printf '%s\n' facade/*.cpp | xargs -P "$nproc_val" -I{} "${tidy_cmd[@]}" -p . "${extra_args[@]}" {}

# Advisory, not part of `check`: Clang's `-Weverything` minus pure-noise categories -- C++98
# compat (the facade is C++17), buffer-hardening (it does deliberate raw-pointer work over the
# SDK's C-style API and the ELF GOT-rewrite trap), and padding notices. What's left (old-style
# casts, switch-enum, sign-conversion, ...) is real signal to triage by hand.
pedantic:
    #!/usr/bin/env bash
    set -uo pipefail
    IDAKIT_EMIT_COMPILE_COMMANDS=1 cargo build -q -p idakit-sys
    cd crates/idakit-sys
    sdk_include="$(jq -r '.[0].arguments[(.[0].arguments | index("-isystem")) + 1]' compile_commands.json)"
    extra_args=(-isystem "$sdk_include")
    if [ "$(uname -s)" = Darwin ]; then
      extra_args+=(-isysroot "$(xcrun --show-sdk-path)")
    fi
    # `-Weverything` shifts across Clang releases; prefer a `clang++` matching clang-tidy's
    # major over the ambient one, which may be older and reject (then warn about) these flags.
    clang_major="$(clang-tidy --version | grep -oE 'version [0-9]+' | grep -oE '[0-9]+')"
    clangxx="clang++"
    command -v "clang++-$clang_major" >/dev/null 2>&1 && clangxx="clang++-$clang_major"
    nproc_val="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
    printf '%s\n' facade/*.cpp | xargs -P "$nproc_val" -I{} \
      "$clangxx" -std=c++17 -Ifacade "${extra_args[@]}" -D__EA64__ -D__LINUX__ \
      -Weverything -Wno-c++98-compat -Wno-c++98-compat-local-type-template-args \
      -Wno-unsafe-buffer-usage -Wno-unsafe-buffer-usage-in-libc-call -Wno-padded \
      -fsyntax-only {}

# ASan+UBSan (facade too) or ThreadSanitizer against the real kernel across the FFI boundary;
# nightly-only (needs -Z build-std). `mode` is "address" or "thread"; UBSan rides only on the
# C++ side (rustc has no `-Zsanitizer=undefined`, and its runtime is ASan xor TSan). Leak
# detection is off -- IDA's kernel is a process-lifetime singleton, so LSan's exit findings all
# sit in libida.so, not real leaks. Thread mode carries a suppressions file for the same
# reason: see crates/idakit-sys/tsan-suppressions.txt.
sanitize mode="address":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{ mode }}" = thread ]; then
      export IDAKIT_SANITIZE=thread
      export RUSTFLAGS="-Zsanitizer=thread -Cdebuginfo=1"
      export TSAN_OPTIONS="suppressions=$(pwd)/crates/idakit-sys/tsan-suppressions.txt"
    else
      export IDAKIT_SANITIZE=address,undefined
      export RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=1"
      export ASAN_OPTIONS=detect_leaks=0
    fi
    cargo +nightly test -Z build-std --target x86_64-unknown-linux-gnu -p idakit --test roundtrip

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build API docs, warnings-as-errors (broken links, bad code blocks, bare URLs, invalid HTML
# tags in example doc comments all fail). Default scrapes example call-sites onto each item
# (nightly + real runtime); `hermetic` skips scraping and builds under DOCS_RS, so no IDA
# runtime -- CI and `check` use it. Both pass --examples so example `//!` doc comments are
# linted too, not just the library crates.
doc mode="scrape":
    RUSTDOCFLAGS="-D warnings" {{ if mode == "hermetic" { "DOCS_RS=1 cargo doc --workspace --all-features --no-deps --examples" } else { "cargo +nightly doc --workspace --all-features --no-deps --examples -Z rustdoc-scrape-examples" } }}

# Lint the GitHub Actions workflows (auto-discovers .github/workflows/).
actionlint:
    actionlint

# README.md's generated block is idakit's crate-level `//!` doc, run through cargo-rdme so the
# two can't drift; intra-doc links resolve to live docs.rs URLs, which needs the pinned nightly
# `cargo rdme install-rust-toolchain-for-intralinks` installs. DOCS_RS=1 skips the native IDA
# link, same as `doc hermetic`.
readme:
    DOCS_RS=1 cargo rdme --manifest-path crates/idakit/Cargo.toml --heading-base-level 1 --force

readme-check:
    DOCS_RS=1 cargo rdme --manifest-path crates/idakit/Cargo.toml --heading-base-level 1 --check

# Like `test`, but --no-fail-fast so one run surfaces every platform's failures. In CI the
# fetch-corpus step exports IDAKIT_CORPUS_MANIFEST, so the dedicated tests source the same
# host-independent canonical fixture the corpus matrix uses.
ci-test:
    cargo nextest run --workspace --all-features --no-fail-fast
    cargo test --workspace --all-features --doc
