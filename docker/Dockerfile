# syntax=docker/dockerfile:1.7
# One image for every server role: `orbyn serve`, `orbyn worker`, `orbyn migrate`.
# Build from the repository root: docker build -f docker/Dockerfile -t orbyn-engine .

FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY . .
# Cache mounts keep the registry and target between builds, so only changed
# crates rebuild.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p orbyn-cli \
 && cp target/release/orbyn /orbyn

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /orbyn /usr/local/bin/orbyn
ENV ORBYN_BIND=0.0.0.0:8080 \
    ORBYN_LOG_FORMAT=json
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/orbyn", "health", "127.0.0.1:8080"]
ENTRYPOINT ["/usr/local/bin/orbyn"]
CMD ["serve"]
