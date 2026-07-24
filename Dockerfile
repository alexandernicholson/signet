FROM rust:1.89-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /source/target/release/signet /signet
USER 65532:65532
ENTRYPOINT ["/signet"]
