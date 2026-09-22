# iris-verifier

The server side of Iris face verification for the passport issuer. The issuer
opens a *face session* with the chip portrait, the wallet streams camera
frames to it over a WebSocket, the Iris engine (`libpassportreader`) judges
liveness and matches the face against the portrait, and the issuer reads the
verdict before issuing. The wire protocol and the process model are described
below.

## Licence, and who may run this

This directory is not covered by the repository's Apache 2.0 licence. See
[LICENSE](LICENSE).

**You cannot use this service without your own licence with the manufacturer of
the Iris library**, from [passportreader.app](https://passportreader.app). The
engine that does the face detection, matching and liveness judging is theirs,
not Yivi's, and it is proprietary. The source here is published for review, and
the archive is published with the manufacturer's permission, but neither grants
any right to use the library. Images built from this directory contain it
statically linked and carry the same restriction.

## Process model

One process serves HTTP and WebSockets. Every stream that starts gets a
child process, this same binary re-executed with `--worker`, which links the
C library and owns exactly one verifier (the library keeps it as
process-global state, so two sessions in one process would corrupt each
other). Parent and worker talk over the worker's stdin/stdout with
length-prefixed messages (`protocol.go`): `portrait` and `frame` down,
`state`, `result` or `reject` back. The parent kills the worker at the
terminal state, on timeout and on disconnect. The portrait and every frame
live only in the parent's memory and then the worker's; they never reach the
session store or a log.

Consequence: a stream must reach the replica that created its session,
because the portrait is held in that replica's memory. This holds with the
single replica of the initial deployment. More replicas need sticky routing
or a shared, encrypted portrait store.

## Wire protocol

### Wallet → `GET /stream/{face_session_id}` (WebSocket)

1. Client sends `{"type":"hello","token":"…"}` as the first text message
   (within `IRIS_HANDSHAKE_TIMEOUT_SECONDS`, default 10).
2. Server answers `{"type":"ready","max_frames":900,"max_width":640,"fps":15}`,
   or `{"type":"error","code":"unauthorized|expired|already_streaming"}` and
   closes. One connection per session, ever.
3. Client sends binary frames: a 16-byte little-endian header, `seq` uint32,
   `ts_ms` uint32, `width` uint16, `height` uint16, `orientation` uint8
   (library enum: 0 = 0°, 1 = 90°, 2 = 180°, 3 = 270°), 3 reserved bytes,
   followed by a JPEG.
4. Server sends `{"type":"state","seq":n,"state":"initiated"}` at most every
   500ms, then exactly one terminal message and a close frame:
   `{"type":"result","state":"completed","passed":true,"distance":0.41}`,
   `{"type":"result","state":"failed"}`, or
   `{"type":"error","code":"timeout|too_many_frames|frame_too_large|bad_frame|internal"}`.

Frames that arrive faster than the FPS cadence (server clock) are dropped:
not processed, not counted. Limits: `IRIS_MAX_SECONDS` from the stream
start, `IRIS_MAX_FRAMES` processed frames, `IRIS_MAX_WIDTH` px on either
side, and `IRIS_MAX_FRAME_BYTES` per JPEG. A frame the JPEG decoder or the engine rejects
ends the stream with `bad_frame`. `internal` is not in the plan's list: it
means the verifier itself failed (no worker, store down, portrait on another
replica); the wallet should treat it like any error and start a new session.

`passed = state == COMPLETED && distance <= IRIS_DISTANCE_THRESHOLD`. It is
what the wallet shows the user; the issuer applies its own
`iris_face_match_threshold` to `distance` and gates issuance on that, so the
two can disagree without the issuer's decision moving.

### Issuer → `/internal/sessions` (HTTP, cluster-only; the ingress exposes `/stream` only)

- `POST /internal/sessions` `{"portrait": "<base64 JPEG/PNG>", "portrait_sha256": "<hex>", "document_type": "passport|id_card|driving_licence"}`
  → `200 {"face_session_id": "fs_…", "token": "…", "expires_at": "<RFC 3339>"}`.
  `portrait_sha256` must be the SHA-256 of the decoded portrait bytes, else
  400. The issuer builds the wallet's stream URL from its own configuration
  as `<public origin>/stream/<face_session_id>`.
- `GET /internal/sessions/{id}` → `{"status": "pending|streaming|completed|failed|expired", "passed": bool, "distance": number, "portrait_sha256": "…", "frames": n, "duration_ms": n}`;
  `passed` and `distance` are present only once the engine completed. 404
  once the record is gone. A pending record stays readable as `expired` for
  `IRIS_TERMINAL_TTL_SECONDS` after its deadline. Every stream that ends
  without an engine verdict (timeout, disconnect, bad frame) is `failed`.
- `DELETE /internal/sessions/{id}` → 204, idempotent.

### Health

- `GET /healthz`: the process is up.
- `GET /readyz`: the session store answers and, in builds that carry the
  engine, `--worker --selftest` can start and initialise the library. Returns
  `{"status":"ok","engine":true,"public_stream_url":"…"}`.

## Configuration

Environment variables, as the deployment sets them. Each has a flag of the
same meaning (`iris-verifier -h`), but a set environment variable wins over
its flag. Redis settings are environment-only because they carry a secret.

| Env | Default | Meaning |
|---|---|---|
| `IRIS_LISTEN_ADDR` | `:8081` | listen address |
| `IRIS_PUBLIC_STREAM_URL` | | public `wss://` origin of this service, e.g. `wss://iris-verifier.staging.yivi.app`; reported in logs and `/readyz` only, the issuer builds each session's stream URL itself |
| `IRIS_DISTANCE_THRESHOLD` | `0.75` | a completed session passes when distance ≤ this, for the verdict reported to the wallet; issuance is gated on the issuer's own threshold |
| `IRIS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `IRIS_MAX_FRAMES` | `900` | processed frames per session |
| `IRIS_MAX_SECONDS` | `60` | seconds per session from its start |
| `IRIS_MAX_WIDTH` | `640` | max frame dimension in pixels |
| `IRIS_FPS` | `15` | accepted frame cadence; faster frames are dropped |
| `IRIS_MAX_FRAME_BYTES` | `1048576` | max JPEG bytes per frame |
| `IRIS_PENDING_TTL_SECONDS` | `600` | how long a created session waits for its stream |
| `IRIS_TERMINAL_TTL_SECONDS` | `900` | how long a finished session stays readable |
| `IRIS_HANDSHAKE_TIMEOUT_SECONDS` | `10` | wait for the `hello` message |
| `REDIS_SENTINEL_HOST` | | empty selects the in-memory store |
| `REDIS_SENTINEL_PORT` | `26379` | |
| `REDIS_MASTER_NAME` | | e.g. `yivi-master` |
| `REDIS_USERNAME` | | ACL user = namespace name; also the Sentinel user; keys live under `<username>:iris:` |
| `REDIS_PASSWORD` | | |

In the cluster the Redis values come from the Kubernetes secret `redis`
(keys `sentinel-host`, `sentinel-port`, `master-name`, `username`,
`password`).

Logs are JSON on stderr. Each finished stream also produces one
`event=face_verification` line with `kind=iris_session` through the shared
`analytics` package (`backend/analytics`): outcome
`completed|failed|timeout|abandoned`, `frames`, `duration_ms`,
`per_frame_ms`, and `score`/`score_kind=iris_distance` when the engine
completed.

## Building and running

The engine exists for Linux x86_64 only and links only with clang + lld (see
`third_party/libpassportreader/README.md`). On any other platform the module
builds with a stub engine: `go build`, `go vet` and `go test` all work, and
the fake-worker tests cover the protocol, but a real stream ends with
`internal`.

Image, from the repository root (the module `replace`s `go-passport-issuer`
with `../backend`, so the context must contain both):

    docker build --platform linux/amd64 -f verifier/Dockerfile -t iris-verifier .
    docker run --rm -p 8081:8081 --platform linux/amd64 iris-verifier

The build fetches the engine itself and verifies its checksum, so there is no
separate download step. On Apple Silicon this runs under emulation, which is
far too slow to judge a real stream; benchmark and smoke-test on x86_64.

Native build inside a Linux container:

    apt-get install -y clang lld
    cd verifier
    ./third_party/libpassportreader/fetch.sh
    CC=clang CGO_ENABLED=1 CGO_LDFLAGS_ALLOW='-fuse-ld=lld|-flto' go build -o iris-verifier .

## Tests

    cd verifier && go test ./...

Runs everywhere: pipe protocol, frame header, JPEG → 4:2:0 conversion, the
worker loop with a fake engine, the subprocess plumbing (the test binary
re-executes itself as the worker), both stores' contract (Redis when
`IRIS_TEST_REDIS_ADDR=host:port` is set), and the whole WebSocket protocol
against a fake worker: handshake errors, pacing, every limit, every terminal
message, recording.

Real-library smoke test and benchmarks (`engine_smoke_test.go`, build tag
`linux && amd64 && cgo`), in a Linux x86_64 container with clang and lld:

    CC=clang CGO_ENABLED=1 CGO_LDFLAGS_ALLOW='-fuse-ld=lld|-flto' \
      go test -run 'TestEngine' -v ./...
    IRIS_SMOKE_PORTRAIT=/path/to/face.jpg \
      CC=clang CGO_ENABLED=1 CGO_LDFLAGS_ALLOW='-fuse-ld=lld|-flto' \
      go test -run 'TestEngine' -bench 'Benchmark' -benchtime 100x ./...

Without `IRIS_SMOKE_PORTRAIT` (a JPEG or PNG with a detectable face) the
smoke test covers the face-less portrait → FAILED case and the no-op after a
terminal state; the INITIATED case and the benchmarks need a real face.
`BenchmarkEngineFrame` reports ns per `run` call on decoded 640×480 frames;
`BenchmarkWorkerFrame` includes the JPEG decode, i.e. the per-frame CPU the
capacity plan needs.
