# Huginn MCP server image (Rust).
# Base images pinned by digest (a tag can be re-pointed silently, a digest
# cannot); Dependabot keeps them current (.github/dependabot.yml).
FROM rust:1-slim@sha256:73b81f338853a11a828adeb6fc31ba5d53e3cbc435fb6ae71752473242f6f88b AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Runtime: debian slim + CA roots (the MCP calls the hub over the internal
# network; CA roots allow TLS hubs too). Runs unprivileged like the Python
# image did (uid 10002).
FROM debian:stable-slim@sha256:13f723858144cb70a15a8f5924e1bb3ca2a3e19d29e86fb8adcfd7101ba9e237
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10002 huginn
COPY --from=build /src/target/release/huginn-mcp /usr/local/bin/huginn-mcp
USER huginn
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/huginn-mcp"]
