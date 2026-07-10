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

- `regula_face_api_url` — Regula Face API base URL (e.g. `http://regula-face-api:41101`). When omitted, face verification is disabled.
- `regula_face_match_threshold` — similarity threshold (0-1) above which the live face is considered a match. Defaults to `0.75`.

## Implementation

See `backend/face_verification_client.go` for the Go client implementation.

## Documentation

- [Face SDK Overview](https://docs.regulaforensics.com/develop/face-sdk/)
- [Face SDK Configuration](https://docs.regulaforensics.com/develop/face-sdk/web-service/administration/configuration/)
- [Liveness Detection](https://docs.regulaforensics.com/develop/face-sdk/web-service/development/usage/liveness/)
- [Face SDK API Reference](https://dev.regulaforensics.com/FaceSDK-web-openapi/)
