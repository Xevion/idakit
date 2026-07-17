# Tests read `.env` themselves, but a mutants job runs in a gitignore-filtered copy that `.env`
# never reaches, so IDAKIT_CORPUS_MANIFEST has to arrive through the environment instead.
set dotenv-load := true

facade_cpp := "crates/idakit-sys/facade/*.cpp"
facade_sources := "crates/idakit-sys/facade/*.cpp crates/idakit-sys/facade/*.h"

default:
    @just --list

# One-stop gate mirroring CI: a clean run here means CI will very likely pass.
check: fmt-check actionlint zizmor clippy tidy (doc "hermetic") readme-check test

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
    printf '%s\n' {{ facade_cpp }} | xargs -P "$nproc_val" -I{} "${tidy_cmd[@]}" -p crates/idakit-sys "${extra_args[@]}" {}

# Advisory, not part of `check`: Clang's `-Weverything` minus pure-noise categories -- C++98
# compat (the facade is C++17), buffer-hardening (it does deliberate raw-pointer work over the
# SDK's C-style API and the ELF GOT-rewrite trap), and padding notices. What's left (old-style
# casts, switch-enum, sign-conversion, ...) is real signal to triage by hand.
pedantic:
    #!/usr/bin/env bash
    set -uo pipefail
    IDAKIT_EMIT_COMPILE_COMMANDS=1 cargo build -q -p idakit-sys
    sdk_include="$(jq -r '.[0].arguments[(.[0].arguments | index("-isystem")) + 1]' crates/idakit-sys/compile_commands.json)"
    out_include="$(jq -r '.[0].arguments[(.[0].arguments | index("-Ifacade")) + 1]' crates/idakit-sys/compile_commands.json)"
    extra_args=(-isystem "$sdk_include" "$out_include")
    if [ "$(uname -s)" = Darwin ]; then
      extra_args+=(-isysroot "$(xcrun --show-sdk-path)")
    fi
    # `-Weverything` shifts across Clang releases; prefer a `clang++` matching clang-tidy's
    # major over the ambient one, which may be older and reject (then warn about) these flags.
    clang_major="$(clang-tidy --version | grep -oE 'version [0-9]+' | grep -oE '[0-9]+')"
    clangxx="clang++"
    command -v "clang++-$clang_major" >/dev/null 2>&1 && clangxx="clang++-$clang_major"
    nproc_val="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
    printf '%s\n' {{ facade_cpp }} | xargs -P "$nproc_val" -I{} \
      "$clangxx" -std=c++17 -Icrates/idakit-sys/facade "${extra_args[@]}" -D__EA64__ -D__LINUX__ \
      -Weverything -Wno-c++98-compat -Wno-c++98-compat-local-type-template-args \
      -Wno-unsafe-buffer-usage -Wno-unsafe-buffer-usage-in-libc-call -Wno-padded \
      -fsyntax-only {}

# ASan+UBSan (facade too) or ThreadSanitizer against the real kernel across the FFI boundary;
# nightly-only (needs -Z build-std). `mode` is "address" or "thread"; UBSan rides only on the
# C++ side (rustc has no `-Zsanitizer=undefined`, and its runtime is ASan xor TSan). Leak
# detection is off -- IDA's kernel is a process-lifetime singleton, so LSan's exit findings all
# sit in libida.so, not real leaks. Thread mode carries a suppressions file for the same
# reason: see crates/idakit-sys/tsan-suppressions.txt.
#
# Covers the facade's guarded<> boundary plus every binary that marshals a string or buffer
# across it. `--test-threads=1` is mandatory: unlike nextest, plain `cargo test` shares one
# process across a binary's tests, and the kernel singleton hard-errors on a second concurrent
# claim.
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
    tests=(-p idakit -p idakit-sys --test roundtrip --test netnode --test tinfo --test traps
           --test write --test decode_sweep --test strings --test search --test data --test disasm)
    cargo +nightly test -Z build-std --target x86_64-unknown-linux-gnu "${tests[@]}" -- --test-threads=1

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Line coverage over the workspace, written to coverage/ (gitignored); needs cargo-llvm-cov.
# Every step carries the cfg, else the `coverage(off)` exceptions go inert and count against the
# total. Doctests are left out: `--doctests` is still incomplete. Advisory, not part of `check`.
coverage:
    RUSTFLAGS="--cfg coverage_nightly" cargo +nightly llvm-cov nextest --workspace --all-features --no-fail-fast --hide-progress-bar
    RUSTFLAGS="--cfg coverage_nightly" cargo +nightly llvm-cov report --html --output-dir coverage/html
    RUSTFLAGS="--cfg coverage_nightly" cargo +nightly llvm-cov report --lcov --output-path coverage/lcov.info
    RUSTFLAGS="--cfg coverage_nightly" cargo +nightly llvm-cov report --json --output-path coverage/coverage.json

# `just coverage`, then open the HTML report.
coverage-open: coverage
    cargo +nightly llvm-cov report --html --output-dir coverage/html --open

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

# Audits the workflows. Needs a token: the pin audits resolve `uses:` SHAs against GitHub and are
# silently skipped offline.
zizmor:
    GH_TOKEN="$(gh auth token)" zizmor .

# Each crate's README is its crate-level `//!` doc run through cargo-rdme so the two can't drift;
# intra-doc links resolve to live docs.rs URLs, which needs the pinned nightly
# `cargo rdme install-rust-toolchain-for-intralinks` installs. DOCS_RS=1 skips the native IDA
# link, same as `doc hermetic`. The root README.md is idakit's; idakit-sys keeps its own.
readme:
    DOCS_RS=1 cargo rdme --manifest-path crates/idakit/Cargo.toml --heading-base-level 1 --force
    DOCS_RS=1 cargo rdme --manifest-path crates/idakit-sys/Cargo.toml --heading-base-level 1 --force

readme-check:
    DOCS_RS=1 cargo rdme --manifest-path crates/idakit/Cargo.toml --heading-base-level 1 --check
    DOCS_RS=1 cargo rdme --manifest-path crates/idakit-sys/Cargo.toml --heading-base-level 1 --check

# Like `test`, but spells --no-fail-fast rather than leaning on the nextest profile for it. In CI
# the fetch-corpus step exports IDAKIT_CORPUS_MANIFEST, so the dedicated tests source the same
# host-independent canonical fixture the corpus matrix uses.
ci-test:
    cargo nextest run --workspace --all-features --no-fail-fast
    cargo test --workspace --all-features --doc

# Refuses to start a mutants run that cannot check anything. Without a corpus the kernel tests
# skip, pass, and leave every mutant MISSED, which reads exactly like a real result: the whole run
# then reports a coverage hole that does not exist, and buries the ones that do.
[private]
require-corpus:
    #!/usr/bin/env bash
    if [ -z "${IDAKIT_CORPUS_MANIFEST:-}" ] || [ ! -f "${IDAKIT_CORPUS_MANIFEST:-}" ]; then
      echo "IDAKIT_CORPUS_MANIFEST is unset or names no file; set it in .env." >&2
      echo "Without it the kernel tests skip and every mutant reports MISSED against a run that checked nothing." >&2
      exit 1
    fi

# Mutation-tests the modules scoped in .cargo/mutants.toml against the unit tests and dedicated
# kernel binaries. `jobs` stays well under the core count: concurrency nests, since every job
# runs its own build plus test pool, each test holding a live ~0.85 GiB kernel.
mutants jobs="3": require-corpus
    cargo mutants -p idakit --jobs {{ jobs }}

# Like `mutants`, but skips what a previous run already caught or found unviable (accumulated in
# mutants.out/previously_caught.txt). A heuristic: confirm with a full `just mutants` before
# trusting a clean result, since it assumes new tests never reduce coverage elsewhere.
mutants-iterate jobs="3": require-corpus
    cargo mutants -p idakit --jobs {{ jobs }} --iterate

# Only the mutants touching lines changed since `base`, for a per-PR loop.
mutants-diff base="master": require-corpus
    git diff {{ base }}...HEAD > /tmp/idakit-mutants.diff
    cargo mutants -p idakit --in-diff /tmp/idakit-mutants.diff

# One shard of N for CI fan-out, e.g. `just mutants-shard 0/8`.
mutants-shard shard: require-corpus
    cargo mutants -p idakit --shard {{ shard }}

# Only one file's mutants, e.g. `just mutants-file crates/idakit/src/name.rs`, for checking a
# specific fix without paying for the whole tree. Goes through `require-corpus` like the rest:
# a bare `cargo mutants` misses this Justfile's dotenv-load, leaving the kernel tests without a
# corpus to skip against, so every mutant reports MISSED against a run that checked nothing.
#
# Filters with `--re`, not `--file`: mutants.toml's `examine_globs` silently overrides `--file`,
# so the obvious spelling runs the entire tree while reporting that it scoped to one file. `--re`
# matches the `--list` line, which is `<path>:<line>:<col>: <mutant>`, so anchoring on the path
# scopes it. Dots in `file` stay unescaped -- they match themselves in any real path.
mutants-file file jobs="3": require-corpus
    cargo mutants -p idakit --jobs {{ jobs }} --re '{{ file }}:'
