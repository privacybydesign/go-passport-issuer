# Face Verification Setup

## Components

This implementation uses [Regula Face SDK](https://docs.regulaforensics.com/develop/face-sdk/) for face matching and liveness detection. The live face is captured by the client during a Regula liveness session and referenced by a `liveness_transaction_id`; the backend confirms the liveness verdict, matches it against the document chip portrait, then deletes the transaction. See [face-verification-design.md](face-verification-design.md) for the full flow and sequence diagram.

### Required Services

- **Regula Face API** - Face detection, matching (1:1), and liveness assessment
- **PostgreSQL 17** - Stores liveness session metadata (transaction IDs, timestamps, results)
- **pgAdmin** - Database management interface (optional)

### Required Files

- `local-secrets/regula.license` - Regula Face SDK license file
- `local-secrets/facesdk-config.yml` - Face API configuration (copy from `facesdk-config.sample.yml`)

## Running

```bash
docker-compose up -d
```

**Access:**
- Face API: http://localhost:41101
- pgAdmin: http://localhost:5051 (admin@admin.com / admin)

## Configuration

Face API is configured in `local-secrets/facesdk-config.yml`:
- Liveness enabled with filesystem storage
- Face matching (detectMatch) enabled
- PostgreSQL connection for metadata storage

**Database connection from pgAdmin:**
- Host: `db-postgres`
- Port: `5432`
- Database: `regula_db`
- User: `regula` / `Regulapasswd#1`

## Backend Configuration

Enable face verification by setting these keys in the issuer `config.json`:

Each method's settings live in its own block, and every field of a block is
required: a block that is present must be complete, and a method cannot be
enabled without its block. Startup fails, naming the missing key, rather than
running an environment that would dead-end at runtime.

- `regula.face_api_url` — Regula Face API base URL the backend matches against
  over the internal network (e.g. `http://regula-face-api:41101`).
- `regula.face_api_public_url` — browser/app-reachable origin of the same Face
  API (e.g. `https://faceapi.staging.yivi.app`), announced to the app in
  `/api/start-validation` and served to the `/capture` page.
- `face_verification_enabled` — whether face verification applies. Enabled is
  fail-closed: issuance without a matching liveness transaction is rejected.
  Disabled removes the step entirely (no announcement to the app, `/capture`
  off). Omitted means disabled. Enabled requires a complete block for every
  enabled method; startup fails otherwise.
- `regula.face_match_threshold` — similarity in (0, 1] at or above which the
  live face is considered a match. Required; there is no default, because how
  strict face verification is decides who gets a credential and every
  environment should state it rather than inherit it from a release.
- `iris.verifier_url` — cluster-internal base URL of the Iris verifier (e.g.
  `http://iris-verifier-svc:8081`).
- `iris.verifier_public_url` — wallet-reachable origin of the verifier's stream
  endpoint (e.g. `wss://iris-verifier.staging.yivi.app`).
- `iris.face_match_threshold` — the same knob on the Iris scale: the distance
  in (0, 1] at or *below* which the live face is considered a match. Also
  required. The verifier has a threshold of its own
  (`IRIS_DISTANCE_THRESHOLD`) for the verdict it reports to the wallet, but
  issuance is decided by this one, so both methods' strictness lives in this
  config.

The flat keys these replaced (`regula_face_api_url`, `iris_verifier_url`, …)
are refused at startup with a message naming the replacement, so a config that
misses the migration cannot quietly leave face verification off.

## Implementation

See `backend/face_verification_client.go` for the Go client implementation.

## Documentation

- [Face SDK Overview](https://docs.regulaforensics.com/develop/face-sdk/)
- [Face SDK Configuration](https://docs.regulaforensics.com/develop/face-sdk/web-service/administration/configuration/)
- [Liveness Detection](https://docs.regulaforensics.com/develop/face-sdk/web-service/development/usage/liveness/)
- [Face SDK API Reference](https://dev.regulaforensics.com/FaceSDK-web-openapi/)
