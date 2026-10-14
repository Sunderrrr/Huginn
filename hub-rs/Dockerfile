# Huginn hub image (Rust).
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

# Runtime: debian slim + CA roots (OIDC/HTTPS outcalls). Runs unprivileged
# like the Python hub did (uid 10001).
FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 huginn
COPY --from=build /src/target/release/huginn-hub /usr/local/bin/huginn-hub
USER huginn
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/huginn-hub"]
