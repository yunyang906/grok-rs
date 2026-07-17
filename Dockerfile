FROM golang:1.26-alpine AS engine-builder
ARG CLIPROXY_REF=106270bea6f18ba2f2cc8b0b5887987f2874eed8
RUN apk add --no-cache git
RUN git clone https://github.com/router-for-me/CLIProxyAPI.git /src \
    && git -C /src checkout "$CLIPROXY_REF"
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cli-proxy-api ./cmd/server

FROM rust:1.92-alpine AS rust-builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY static ./static
RUN cargo build --release

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=engine-builder /out/cli-proxy-api /app/cli-proxy-api
COPY --from=rust-builder /src/target/release/grok-rs /app/grok-rs
ENV BIND=0.0.0.0:8991 \
    GROK_ENGINE_BIN=/app/cli-proxy-api \
    GROK_ENGINE_CONFIG=/data/engine.yaml
VOLUME ["/data"]
EXPOSE 8991
ENTRYPOINT ["/app/grok-rs"]
