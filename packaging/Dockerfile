# Build on Debian 12 so releases do not depend on the build host's newer glibc.
FROM rust:1.98.1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfontconfig1-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev \
    libx11-dev libxcursor-dev libxi-dev libxrandr-dev libxcb1-dev \
    dbus pkg-config python3 zstd rpm && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY extension/public ./extension/public
COPY extension/lib/browser-identities.json ./extension/lib/browser-identities.json
COPY extension/lib/password-words.ts ./extension/lib/password-words.ts
COPY extension/protocol ./extension/protocol
COPY packaging ./packaging
COPY scripts ./scripts
COPY README.md LICENSE ./
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
RUN python3 scripts/third-party-notices.py rust THIRD_PARTY_NOTICES.txt
RUN cargo test --locked -- --test-threads=1 && cargo build --release --locked
RUN python3 scripts/package-release.py --binary target/release/boltwarden --output /artifacts
FROM scratch AS artifacts
COPY --from=build /artifacts/ /
