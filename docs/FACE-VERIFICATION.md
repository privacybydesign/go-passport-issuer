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

- `regula_face_api_url` — Regula Face API base URL the backend matches against
  over the internal network (e.g. `http://regula-face-api:41101`).
- `regula_face_api_public_url` — browser/app-reachable origin of the same Face
  API (e.g. `https://faceapi.staging.yivi.app`), announced to the app in
  `/api/start-validation` and served to the `/capture` page.
- `face_verification_enabled` — whether face verification applies. Enabled is
  fail-closed: issuance without a matching liveness transaction is rejected.
  Disabled removes the step entirely (no announcement to the app, `/capture`
  off). When omitted, derived from `regula_face_api_url` (set → enabled,
  unset → disabled). Enabled requires both URLs above; startup fails
  otherwise.
- `regula_face_match_threshold` — similarity threshold (0-1) above which the live face is considered a match. Defaults to `0.75`.
- `face_matcher_url` — base URL of the self-hosted [face-matcher](../face-matcher/README.md)
  sidecar (e.g. `http://face-matcher:8000`). Set → on-device face verification
  (variant B, the Iris SDK in the app) is offered: the app submits the live face
  crop the SDK captured and the backend re-matches it against the chip portrait
  here. Independent of the Regula keys; a deployment may configure only this and
  run no Regula at all.
- `face_matcher_threshold` — cosine similarity above which the face matcher
  considers the live crop and the chip portrait the same person. Required
  (positive) when `face_matcher_url` is set. No default: the scale differs from
  Regula's and must be calibrated per deployment.

`/api/start-validation` announces which methods the issuer accepts in
`face_verification.methods` (`["regula"]`, `["iris"]` or both); `face_api_url`
is only present when `regula` is among them.

## On-device face verification (variant B)

The app runs liveness and matching on the device with the Iris SDK and submits
the resulting live face crop instead of a liveness transaction id:

```json
{
  "session_id": "…",
  "nonce": "…",
  "data_groups": { … },
  "ef_sod": "…",
  "face_verification": {
    "method": "iris",
    "live_face_png": "<base64 PNG>",
    "client_outcome": "matched"
  }
}
```

The backend validates the PNG (size and dimension bounds), decodes the raw DG2
or DG6 chip image, and asks the face-matcher sidecar for the similarity between
the two. Issuance is fail-closed exactly as for Regula: any error or a
similarity below `face_matcher_threshold` is a `400`. `client_outcome` is
informational only, logged next to the server-side result so client/server
disagreement can be measured. The crop is request-scoped and never stored.

A request may carry either `liveness_transaction_id` or `face_verification`,
never both; mixed evidence is rejected. Evidence for a method the issuer does
not offer (a transaction id at a matcher-only issuer, or a crop at a
Regula-only issuer) is rejected as well rather than skipped.

## Implementation

See `backend/face_verification_client.go` for the Go client implementation.

## Documentation

- [Face SDK Overview](https://docs.regulaforensics.com/develop/face-sdk/)
- [Face SDK Configuration](https://docs.regulaforensics.com/develop/face-sdk/web-service/administration/configuration/)
- [Liveness Detection](https://docs.regulaforensics.com/develop/face-sdk/web-service/development/usage/liveness/)
- [Face SDK API Reference](https://dev.regulaforensics.com/FaceSDK-web-openapi/)
