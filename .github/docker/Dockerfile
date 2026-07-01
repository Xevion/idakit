# syntax=docker/dockerfile:1.7
#
# The build/test environment only: Rust toolchain + IDA runtime. No idakit source or baked
# build -- the workspace build, SDK-header fetch, and EULA acceptance happen per-run in CI.
# IDA is a named build context (`ida`), not copied into the repo; `just ci-image` wires it:
#
#   docker build -f .github/docker/Dockerfile --build-context ida="$IDADIR" -t idakit-ci .

# Keep in sync with rust-toolchain.toml's `channel`.
FROM rust:1.96.1-bookworm

# g++: the C++ facade (cc crate). git: SDK-header fetch in build.rs. just: the test recipe.
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
       | bash -s -- --to /usr/local/bin

# The base image ships neither; CI runs clippy and cargo fmt.
RUN rustup component add clippy rustfmt

# build.rs links libida.so/libidalib.so from here; LD_LIBRARY_PATH is for the stock tools.
ENV IDADIR=/opt/ida
ENV LD_LIBRARY_PATH=/opt/ida
COPY --from=ida . /opt/ida/

# Runs as root (image default): GitHub container jobs need it (the runner owns the mounted
# /__w dirs, so a non-root user hits EACCES in actions/checkout), and the kernel wants a
# writable $HOME. rust-cache persists this SDK cache; cargo dirs keep base/workspace defaults.
ENV IDA_SDK_CACHE_DIR=/root/.cache/idakit/ida-sdk

# Links the (private) package to the repo so the workflow's GITHUB_TOKEN can pull it.
LABEL org.opencontainers.image.source=https://github.com/Xevion/idakit
