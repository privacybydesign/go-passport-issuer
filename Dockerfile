FROM node:23-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend .
RUN npm install
RUN npm run build

# -----------------------------------------------------

FROM golang:1.24 AS backend-build
WORKDIR /app/backend
COPY backend .
RUN go mod download

# compile with static linking
RUN CGO_ENABLED=0 go build -o server 

# -----------------------------------------------------

FROM alpine:latest

COPY --from=backend-build /app/backend/server /app/backend/server
COPY --from=frontend-build /app/frontend /app/frontend

WORKDIR /app/backend
EXPOSE 8080
CMD ["./server", "--config", "/secrets/config.json"]