# syntax=docker/dockerfile:1.7
# The Cactarium server image. Build context: the repo root.

FROM rust:1.96-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p cactarium-server && cp target/release/cactarium /cactarium

FROM debian:trixie-slim
# git: the tracker lists and fetches tags from authors' repos.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/cactarium --create-home cactarium
COPY --from=build /cactarium /usr/local/bin/cactarium
COPY crates/cactarium-server/static /srv/cactarium/static
ENV CACTARIUM_STATIC_DIR=/srv/cactarium/static \
    CACTARIUM_BIND=0.0.0.0:8000 \
    RUST_LOG=info,sqlx=warn
USER cactarium
EXPOSE 8000
ENTRYPOINT ["cactarium"]
CMD ["serve"]
