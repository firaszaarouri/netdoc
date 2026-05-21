# netdoc — multi-stage Docker build producing a tiny scratch image.
#
# Build:   docker build -t netdoc:dev .
# Run:     docker run --rm netdoc:dev github.com
# Run JSON: docker run --rm netdoc:dev --json github.com
#
# GoReleaser also builds and pushes signed multi-arch images to
# ghcr.io/<owner>/netdoc:<tag> on every tagged release. This Dockerfile
# is what GoReleaser invokes via the `dockers:` section of
# .goreleaser.yml — it expects the binary to already be in the build
# context (GoReleaser cross-compiles it first).

# When GoReleaser invokes this, it copies the pre-built binary into the
# context root. For a plain `docker build .` invocation, the COPY below
# expects you to have run `go build -o netdoc .` first.
FROM scratch

# CA certificates needed for TLS / HTTPS probes to verify chains.
# GoReleaser's docker template can also copy these from a builder stage;
# we keep this Dockerfile simple by relying on the host build to have
# included a static binary with embedded certs (Go's crypto/x509 has
# system-store fallbacks but they require /etc/ssl/certs on Linux).
#
# Practical workaround: copy from a slim image at build time.
COPY --from=alpine:3.20 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The binary. GoReleaser places it at the context root; for local
# `docker build .` invocations, run `go build -o netdoc .` first.
COPY netdoc /usr/local/bin/netdoc

# Run as non-root for least-privilege. We don't need root for any of
# netdoc's features (that's literally the brand promise).
USER 65534:65534

ENTRYPOINT ["/usr/local/bin/netdoc"]
CMD ["--help"]
