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
# plain HTTP here) -- unlike authside itself it is a client, so it keeps a
# CA bundle via base-debian12 rather than the certless "static" variant,
# in case anyone points OIDC_ISSUER at a real https:// endpoint instead.
FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /out/app /app

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
