# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Custom Postgres 18 image for Zagrosi: stock postgres:18-bookworm plus
# pg_partman (month-partitioned audit_events maintenance, incl. the BGW) and
# pg_parquet (cold archival via COPY ... TO 's3://...' (format 'parquet')).
#
# ARG defaults mirror deploy/docker/postgres/VERSIONS (the single source of
# truth, asserted by smoke.sh); bump both together with IMAGE_TAG.
# The pg_parquet stage compiles Rust (pgrx) — expect 15-30 minutes cold.
# This image is prebuilt and published by .github/workflows/postgres-image.yml;
# per-PR CI pulls the IMAGE_TAG reference and never rebuilds it.

ARG PG_MAJOR=18

FROM postgres:${PG_MAJOR}-bookworm AS build
ARG PG_MAJOR
ARG PG_PARTMAN_VERSION=5.4.3
ARG PG_PARQUET_VERSION=0.5.1
ARG CARGO_PGRX_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        "postgresql-server-dev-${PG_MAJOR}" \
        pkg-config \
        libssl-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# pg_partman (default make target includes pg_partman_bgw.so — do not set NO_BGW)
RUN git clone --depth 1 --branch "v${PG_PARTMAN_VERSION}" \
        https://github.com/pgpartman/pg_partman.git /build/pg_partman \
    && make -C /build/pg_partman \
    && make -C /build/pg_partman install

# pg_parquet (pgrx-based; pgrx pin must match the release's Cargo.toml)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
    && cargo install --locked cargo-pgrx --version "${CARGO_PGRX_VERSION}" \
    && cargo pgrx init "--pg${PG_MAJOR}" "$(command -v pg_config)"
RUN git clone --depth 1 --branch "v${PG_PARQUET_VERSION}" \
        https://github.com/CrunchyData/pg_parquet.git /build/pg_parquet \
    && cd /build/pg_parquet \
    && cargo pgrx install --release --pg-config "$(command -v pg_config)"

FROM postgres:${PG_MAJOR}-bookworm
ARG PG_MAJOR

LABEL org.opencontainers.image.source="https://github.com/zagrosi-code/zagrosi" \
      org.opencontainers.image.description="Postgres ${PG_MAJOR} with pg_partman and pg_parquet for Zagrosi" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Extension binaries + SQL/control files only — no toolchain in the final image.
COPY --from=build "/usr/lib/postgresql/${PG_MAJOR}/lib/pg_partman_bgw.so" "/usr/lib/postgresql/${PG_MAJOR}/lib/"
COPY --from=build "/usr/lib/postgresql/${PG_MAJOR}/lib/pg_parquet.so" "/usr/lib/postgresql/${PG_MAJOR}/lib/"
COPY --from=build "/usr/share/postgresql/${PG_MAJOR}/extension/pg_partman*" "/usr/share/postgresql/${PG_MAJOR}/extension/"
COPY --from=build "/usr/share/postgresql/${PG_MAJOR}/extension/pg_parquet*" "/usr/share/postgresql/${PG_MAJOR}/extension/"

# BGW/preload templating hook: ships in the image so testcontainers and Helm
# get it without mounts. CREATE EXTENSION stays the consumers' job
# (migrations / tests); nothing is pre-created in template1.
COPY initdb/01-partman-bgw.sh /docker-entrypoint-initdb.d/01-partman-bgw.sh
