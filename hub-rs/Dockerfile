# Huginn hub image (Rust).
# The base images are pinned by digest, not by tag: a tag can be re-pointed
# silently, a digest cannot. Dependabot keeps the digests current (see
# .github/dependabot.yml).
FROM rust:1-slim@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
# jsonwebtoken runs on the `aws_lc_rs` backend (see Cargo.toml): aws-lc-sys
# builds BoringSSL with CMake, so the build stage needs cmake + a generator
# (make). The runtime stage is a separate, slim image — none of this ships.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

# Runtime: debian slim + CA roots (OIDC/HTTPS outcalls). Runs unprivileged
# like the Python hub did (uid 10001).
FROM debian:stable-slim@sha256:a717a33469731894e77e912ea7d714e27c2dc38ee6554fd1a3102e92999cfc66
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 huginn
COPY --from=build /src/target/release/huginn-hub /usr/local/bin/huginn-hub
USER huginn
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/huginn-hub"]
