# Huginn MCP server image (Rust).
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Runtime: debian slim + CA roots (the MCP calls the hub over the internal
# network; CA roots allow TLS hubs too). Runs unprivileged like the Python
# image did (uid 10002).
FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10002 huginn
COPY --from=build /src/target/release/huginn-mcp /usr/local/bin/huginn-mcp
USER huginn
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/huginn-mcp"]
