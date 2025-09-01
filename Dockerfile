# ---------- Frontend ----------
FROM node:23-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend .
RUN npm install
RUN npm run build

# ---------- Backend build (needs CGO + IM6 dev headers) ----------
FROM golang:1.24-bookworm AS backend-build
WORKDIR /app/backend

# Imagick (IM6) build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libmagickwand-6.q16-dev \
  && rm -rf /var/lib/apt/lists/*

COPY backend .
RUN go mod download

# Build with CGO enabled (required by imagick bindings)
ENV CGO_ENABLED=1
RUN go build -o server

# ---------- Runtime (Debian, not Alpine; includes IM6 + JP2 delegate) ----------
FROM debian:bookworm-slim

# Runtime deps: ImageMagick 6 Wand lib + OpenJPEG (JP2) + certs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates imagemagick libmagickwand-6.q16-6 libopenjp2-7 \
  && rm -rf /var/lib/apt/lists/*

# Copy artifacts
COPY --from=backend-build /app/backend/server /app/backend/server
COPY --from=frontend-build /app/frontend /app/frontend

WORKDIR /app/backend
EXPOSE 8080
CMD ["./server", "--config", "/secrets/config.json"]
