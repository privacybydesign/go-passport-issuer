# syntax=docker/dockerfile:1
# iris-verifier image. Build from the repository root, because the verifier
# module replaces go-passport-issuer with ../backend:
#
#   docker build --platform linux/amd64 -f verifier/Dockerfile -t iris-verifier .
#
# The vendor archive is LLVM bitcode from clang 14 plus a few native objects;
# GNU ld refuses it, so the build stage uses clang with lld and allows the
# two linker flags cgo would otherwise reject.
#
# The archive is not in the build context: the build fetches it from a release
# and checks it against a pinned SHA-256. Point the build elsewhere with
#   --build-arg LIBPASSPORTREADER_URL=…
# Publishing an image built here is subject to verifier/LICENSE: it contains
# the proprietary Iris engine statically linked.

FROM golang:1.26-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends clang lld \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY backend/go.mod backend/go.sum /src/backend/
COPY verifier/go.mod verifier/go.sum /src/verifier/
WORKDIR /src/verifier
RUN go mod download

COPY backend/ /src/backend/
COPY verifier/ /src/verifier/

# Fetch and verify the engine. The script is the same one developers run, so
# the checksum is pinned in exactly one place.
ARG LIBPASSPORTREADER_RELEASE
ARG LIBPASSPORTREADER_SHA256
ARG LIBPASSPORTREADER_BASE_URL
ARG LIBPASSPORTREADER_URL
RUN ./third_party/libpassportreader/fetch.sh

ENV CC=clang CGO_ENABLED=1 CGO_LDFLAGS_ALLOW='-fuse-ld=lld|-flto'
RUN go build -trimpath -o /out/iris-verifier .

# The library links statically; the runtime needs only libstdc++ and certs.
FROM debian:bookworm-slim

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libstdc++6 ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --no-create-home iris

COPY --from=build /out/iris-verifier /usr/local/bin/iris-verifier

USER iris
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/iris-verifier"]
