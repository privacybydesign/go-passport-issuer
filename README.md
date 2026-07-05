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

### Document authentication and issuance policy

Each document goes through two independent checks before a credential is issued. Only one of them gates issuance.

#### Passive authentication (mandatory)

Passive authentication verifies the digital signature over the document data (the Document Security Object, SOD) against the trusted CSCA certificates. This proves the data was issued by a genuine authority and has not been tampered with. **Passive authentication is mandatory:** if it fails, the request is rejected with `400` and no credential is issued.

#### Active Authentication / chip-liveness (recorded, not gated)

Active Authentication is a challenge-response with the document chip's private key that proves the chip is physically present ("chip-liveness"), guarding against cloned chips. In this service Active Authentication is **not** a hard requirement for issuance. The behaviour is:

- **Not attempted** (the client supplied no `nonce` / `aa_signature`, or the document has no Active Authentication key present, e.g. no `DG15` for passports/ID cards or no `DG13` for driving licences): the credential is **still issued**.
- **Attempted and successful:** the credential is issued.
- **Attempted and failed** (an invalid `aa_signature`): the request is **rejected** with `400`; no credential is issued.

In other words, a *failed* chip-liveness proof blocks issuance, but a *missing* one does not. This is a deliberate design choice: not every document chip supports Active Authentication, and requiring it would prevent issuance for those documents.

The outcome is recorded in the issued credential's `activeAuthentication` attribute (`"Yes"` when the chip-liveness proof succeeded, `"No"` otherwise) so that relying parties who need cloned-chip protection can require `activeAuthentication == "Yes"` (a case-sensitive match) when verifying the credential. The `/verify-passport` and `/verify-driving-licence` endpoints expose the same information in real time via the `authentic_chip` field of their response.

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
