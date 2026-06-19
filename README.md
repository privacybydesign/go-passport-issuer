[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
[![codecov](https://codecov.io/gh/privacybydesign/go-passport-issuer/graph/badge.svg?token=MMYA8CAG1F)](https://codecov.io/gh/privacybydesign/go-passport-issuer)

# Go Passport Issuer
The Go Passport Issuer repository implements a digital passport issuance system that bridges traditional government-issued travel documents with modern privacy-preserving digital identity frameworks. The system validates electronic passport (e-passport) data using Machine Readable Travel Document (MRTD) standards and issues privacy-by-design digital credentials through the IRMA framework.

## Getting started

### Prerequisites

#### For Local Development (without Docker)

**Go**: Version 1.24.0 or later

**Node.js**: Version 16 or later (for frontend)

**ImageMagick 6**: Required for image processing

- **macOS**:
  ```bash
  brew install imagemagick@6
  ```

- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt-get update
  sudo apt-get install libmagickwand-dev
  ```

### Configuration
Make sure there is a `local-secrets` folder in the root directory with a `config.json` file containing the necessary configuration details.
It should look like this:

```json
{
  "server_config": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "irma_server_url": "https://is.staging.yivi.app",
  "issuer_id": "passport_issuer",
  "jwt_private_key_path": "local-secrets/private.pem",
  "credentials": {
    "passport" : {
      "full_credential": "pbdf-staging.pbdf.passport"
    },
    "driving_licence": {
      "full_credential": "pbdf-staging.pbdf.drivinglicence"
    }
    "id_card": {
      "full_credential": "pbdf-staging.pbdf.idcard"
    }
  },
  "storage_type": "memory",
  "driving_licence_cert_paths": [
    "./certificates/v1/CSCA NL eDL-01.cer",
    "./certificates/v2/CSCA NL eDL-02.cer",
    "./certificates/v3/CSCA NL eDL-03.cer"
  ]
}
```
The `jwt_private_key_path` should point to a valid RSA private key in PEM format, which is used to sign JWT tokens for the IRMA server.

#### Face verification (optional)

The issuer can optionally start a session at a
[face verification service](https://github.com/privacybydesign/face-verification-service)
when validating a passport. When configured, `POST /api/verify-passport` creates
a session bound to the chip's DG2 portrait and returns it as a `face_session`
field in the response. The integration is **off by default**: when no `url` is set
the behaviour is unchanged.

The reference photo sent to the face service is the **original, unmodified DG2
bytes** (base64-encoded), not a re-encoded image. The binding key is derived from
`SHA256(reference_photo)`, and the mobile app derives the same key over the raw
DG2 it read from the chip — so both sides must hash identical bytes.

Add a `face_verification` block to enable it:

```json
{
  "face_verification": {
    "url": "https://face.example.com",
    "verifier_id": "passport-issuer",
    "callback_url": "https://issuer.example.com/api/face/callback",
    "timeout_seconds": 10,
    "require_face_for_issuance": true
  }
}
```

- `url` — base URL of the face verification service (the configurable endpoint). Leave empty to disable.
- `verifier_id` — identifier of this issuer as known to the face service (defaults to `passport-issuer`).
- `callback_url` — URL the face service calls with the signed result. Point it at the issuer's
  `POST /api/face/callback` route.
- `timeout_seconds` — optional HTTP timeout (defaults to 10).
- `require_face_for_issuance` — optional; defaults to `true` when `url` is set. When `true`, issuance of
  all document types (passport, ID card, driving licence) is **gated** on a successful face verification.
  Set `false` to run face verification as advisory only (the session is started and the result surfaced,
  but issuance is not blocked).

The `binding_secret` returned by the face service is used to authenticate result
callbacks and is intentionally never exposed in the validation response.

#### Gated issuance flow

When face verification is required, the full flow is:

1. `POST /api/start-validation` → `{ session_id, nonce }`.
2. `POST /api/verify-passport` (or `/api/verify-driving-licence`) performs passive + active authentication
   and, on success, starts a face session bound to the chip's portrait — **DG2** for passports/ID cards,
   **DG6** for driving licences — returning it as `face_session`. The validation session is **kept** (not
   consumed) so it can be reused by issuance.
3. The wallet streams to the face service; on completion the face service POSTs a signed result to
   `callback_url` (`POST /api/face/callback`), authenticated by `HMAC-SHA256(binding_secret, …)`.
4. `POST /api/issue-passport` (or `/api/issue-id-card`, `/api/issue-driving-licence`) with the
   `face_session_id` from step 2 issues the credential only when **both** authentication and face
   verification succeeded, and the request's portrait data group hashes to the same portrait the face
   session was created with. If the result has not yet arrived the issuer polls the face service's status
   endpoint; while still pending it responds `428` with `face:pending`. A failed or missing verdict yields
   `403` (`face:failed` / `face:required` / `face:mismatch`).

See [`docs/verification-flow-contracts.md`](docs/verification-flow-contracts.md) for the full contract.

### Running the application

#### Local Development (without Docker)

**Setup Environment (macOS)**:
```bash
# Option 1: Use the setup script
source ./dev-setup.sh

# Option 2: Manually set environment variables
export PKG_CONFIG_PATH="/opt/homebrew/opt/imagemagick@6/lib/pkgconfig"
export CGO_CFLAGS_ALLOW="-Xpreprocessor"
```

**Setup Environment (Linux)**:
```bash
# Usually no extra environment variables needed on Linux
# Just ensure ImageMagick development libraries are installed
```

**Run the backend**:
```bash
cd backend
go run . --config ../local-secrets/config.json
```

**Run tests**:
```bash
# On macOS (ensure environment is set up first)
source ../dev-setup.sh
cd backend
go test ./...

# On Linux
cd backend
go test ./...
```

**Run the frontend**:
```bash
cd frontend
npm install
npm start
```

### API Documentation

The backend serves interactive API documentation using ReDoc at `/api/docs`. The OpenAPI specification is generated from Go code annotations using [swaggo/swag](https://github.com/swaggo/swag).

**View documentation**: Navigate to `http://localhost:8080/api/docs` when the server is running.

**Regenerate documentation** (after modifying API handlers or models):
```bash
# Install swag CLI (one-time setup)
go install github.com/swaggo/swag/cmd/swag@latest

# Regenerate docs
cd backend
go generate ./...
```

The swag annotations are located in:
- `backend/main.go` - API metadata (title, version, description)
- `backend/server.go` - Handler annotations
- `backend/models/` - Request/response model annotations

#### Using Docker Compose

To run both the backend and frontend using Docker Compose, ensure you have Docker and Docker Compose installed. Then, from the root directory of the project, execute:
```bash
docker-compose up --build
```

### Troubleshooting

**Issue**: `invalid flag in pkg-config --cflags: -Xpreprocessor` error on macOS

**Solution**: Make sure you're using ImageMagick 6 (not 7) and have set the `CGO_CFLAGS_ALLOW` environment variable:
```bash
brew install imagemagick@6
export PKG_CONFIG_PATH="/opt/homebrew/opt/imagemagick@6/lib/pkgconfig"
export CGO_CFLAGS_ALLOW="-Xpreprocessor"
```

**Issue**: `wand/MagickWand.h file not found`

**Solution**: This indicates ImageMagick is not properly installed or the `PKG_CONFIG_PATH` is not set correctly. Verify installation:
```bash
brew list imagemagick@6
pkg-config --cflags --libs MagickWand
```

## Funding

This project received funding through [NGI0 Commons Fund](https://nlnet.nl/commonsfund), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/Yivi-AgeVerification).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/commonsfund)
