# syntax=docker/dockerfile:1.7
#
# Minimal demo OIDC relying party for examples/compose. Build context is
# the repo root (see ../compose.yaml's `build.context: ../..`) because this
# program is package main inside the authside module itself -- it needs no
# go.mod of its own and adds no new dependency (it only imports
# github.com/coreos/go-oidc/v3 and golang.org/x/oauth2, both already
# required by the root go.mod).

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/app \
    ./examples/compose/app

# This demo app DOES make an outbound HTTPS-capable call (OIDC discovery
# and token exchange against authside over the compose network, which is
# plain HTTP here), so pointing OIDC_ISSUER at a real https:// endpoint has
# to keep working. That does not need base-debian12: the "static" variant
# ships /etc/ssl/certs/ca-certificates.crt too -- what base adds is glibc
# and libssl, neither of which a CGO_ENABLED=0 binary uses. This image was on
# base for exactly that mistaken reason: dropping it takes it from 37.9MB to
# 8.65MB, and it still completes verified HTTPS discovery -- checked by
# running this image with OIDC_ISSUER=https://accounts.google.com, which
# logs "discovered provider" and serves.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/app /app

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
