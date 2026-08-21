# syntax=docker/dockerfile:1.7

# authside is a FAKE OpenID Connect provider for local development and test
# environments only -- see README.md's warning block. This image packages
# cmd/authside as a small, non-root, statically linked binary.

ARG GO_VERSION=1.26

# ---- build stage -----------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG AUTHSIDE_VERSION=dev

# CGO_ENABLED=0 gives a static binary with no libc dependency, which is
# what lets the final stage be distroless "static" (no shared libraries at
# all) rather than needing glibc/musl in the runtime image.
#
# AUTHSIDE_VERSION is injected into main.version, so `authside --version`
# inside the image reports the release it was built from. Without the -X
# the arg would only reach the OCI label below, and the binary would say
# "dev" in an image tagged v1.2.3 -- see cmd/authside/version.go.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${AUTHSIDE_VERSION}" \
    -o /out/authside \
    ./cmd/authside

# ---- runtime stage ----------------------------------------------------------
# distroless/static has no shell, no package manager, and (relevantly) no CA
# certificate bundle. That's still a fit now that --probe exists: authside
# otherwise only accepts inbound requests, and the probe's one outbound GET
# does not verify certificates by design (it asks whether something answers
# at advertise.internal, sends nothing and trusts nothing -- see
# cmd/authside/probe.go), so it needs no roots to trust. Anything added later
# that makes a *verified* outbound HTTPS call does need them: switch this
# base to gcr.io/distroless/base-debian12:nonroot, or add a CA bundle
# explicitly, at that point.
#
# The "nonroot" variant/tag ships a pre-created, unprivileged "nonroot"
# user (uid/gid 65532) and already runs as that user by default; USER below
# is kept explicit rather than relied upon implicitly, so this stays true
# even if the base tag is ever changed to a non-"nonroot" variant.
FROM gcr.io/distroless/static-debian12:nonroot

ARG AUTHSIDE_VERSION=dev
LABEL org.opencontainers.image.title="authside" \
      org.opencontainers.image.description="authside -- a FAKE OpenID Connect provider for local development and test environments. NEVER run in production." \
      org.opencontainers.image.source="https://github.com/mackee/authside" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${AUTHSIDE_VERSION}"

COPY --from=build /out/authside /authside

USER nonroot:nonroot

# Config is never baked into the image: mount a file over
# /etc/authside/authside.yaml (read-only) or set AUTHSIDE_CONFIG_INLINE.
EXPOSE 5556

ENTRYPOINT ["/authside"]

# No --allow-external here by design: the safety gate in cmd/authside/main.go
# (loopback-only unless explicitly opted in) is a deliberate, documented
# default, and an image that silently reached beyond loopback out of the box
# would undo it for every container user without them asking. Compose files
# that need authside reachable from sibling services pass the flag
# themselves in `command:`, exactly as README.md's own sidecar example does
# -- that snippet was the hint this default follows. A bare `docker run` of
# this image (with a config mounted) still starts up correctly; it is just
# loopback-only inside its own network namespace until the caller opts in.
CMD ["--config", "/etc/authside/authside.yaml"]
