# Huginn MCP server image (Rust).
# Base images pinned by digest (a tag can be re-pointed silently, a digest
# cannot); Dependabot keeps them current (.github/dependabot.yml).
FROM rust:1-slim@sha256:1a939748a7cbab172de91a014e3804a97af1394a8c844faa67fce9401c4e40fb AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Runtime: debian slim + CA roots (the MCP calls the hub over the internal
# network; CA roots allow TLS hubs too). Runs unprivileged like the Python
# image did (uid 10002).
FROM debian:stable-slim@sha256:a717a33469731894e77e912ea7d714e27c2dc38ee6554fd1a3102e92999cfc66
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10002 huginn
COPY --from=build /src/target/release/huginn-mcp /usr/local/bin/huginn-mcp
USER huginn
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/huginn-mcp"]
