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
