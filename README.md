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
    },
    "id_card": {
      "full_credential": "pbdf-staging.pbdf.idcard"
    }
  },
  "storage_type": "memory",
  "driving_licence_cert_paths": [
    "./certificates/v1/CSCA NL eDL-01.cer",
    "./certificates/v2/CSCA NL eDL-02.cer",
    "./certificates/v3/CSCA NL eDL-03.cer"
  ],
  "regula_face_api_url": "http://regula-face-api:41101"
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

#### Using Docker Compose

To run both the backend and frontend using Docker Compose, ensure you have Docker and Docker Compose installed. Then, from the root directory of the project, execute:
```bash
docker-compose up --build
```

## Face Verification with Liveness Detection

The Go Passport Issuer integrates with Regula Forensics Face SDK to provide optional face verification during document verification and issuance. The system automatically compares the photo from the document chip (DG2 for passports/ID cards, DG6 for driver's licenses) with a user-provided selfie.

### Features

- **Integrated Face Matching**: Automatically compare document photo with selfie during verification/issuance
- **Optional Verification**: Face matching is only performed when a selfie is provided
- **Liveness Support**: Use Regula's liveness detection in your frontend before sending the selfie
- **Threshold-Based Matching**: Configurable similarity threshold (default 0.75) to determine if faces match

### How It Works

1. User scans document (passport, ID card, or driver's license) via NFC
2. User optionally provides a selfie (after liveness check in frontend)
3. Backend extracts photo from document chip
4. Backend compares document photo with selfie using Regula Face SDK
5. Result includes face match score in verification response
6. For issuance endpoints, face verification can block credential issuance if faces don't match

### Setup

#### 1. Obtain a Regula License

To use the face verification features, you need a valid Regula Forensics license. Contact [Regula Forensics](https://regulaforensics.com/) to obtain a license file.

#### 2. Configure the License

Place your license file in the `local-secrets` directory:

```bash
# Save your license file
cp /path/to/regula.license ./local-secrets/regula.license
```

Or use a Base64-encoded license as an environment variable in `docker-compose.yml`:

```yaml
regula-face-api:
  environment:
    - REGULA_LICENSE=<YOUR_BASE64_ENCODED_LICENSE>
```

#### 3. Enable in Configuration

Add the `regula_face_api_url` to your `config.json`:

```json
{
  ...
  "regula_face_api_url": "http://regula-face-api:41101"
}
```

For local development without Docker, use:
```json
{
  ...
  "regula_face_api_url": "http://localhost:41101"
}
```

### Usage with Existing Endpoints

Face verification is integrated into existing verification and issuance endpoints. Simply add the `selfie_image` field to your requests:

#### Passport/ID Card/Driver's License Verification
```bash
POST /api/verify-passport  # or /api/verify-driving-licence
Content-Type: application/json

{
  "session_id": "session-123",
  "nonce": "nonce-value",
  "data_groups": { ... },
  "ef_sod": "...",
  "selfie_image": "base64-encoded-selfie"  // Optional: include for face verification
}
```

Response with face verification:
```json
{
  "authentic_content": true,
  "authentic_chip": true,
  "is_expired": false,
  "face_match": {
    "matched": true,
    "similarity": 0.87
  }
}
```

#### Passport/ID Card/Driver's License Issuance
```bash
POST /api/issue-passport  # or /api/issue-id-card, /api/issue-driving-licence
Content-Type: application/json

{
  "session_id": "session-123",
  "nonce": "nonce-value",
  "data_groups": { ... },
  "ef_sod": "...",
  "selfie_image": "base64-encoded-selfie"  // Optional: if provided and doesn't match, issuance fails
}
```

**Note**: For issuance endpoints, if `selfie_image` is provided and the face doesn't match (similarity < 0.75), the request will be rejected with status 400.

### Docker Deployment

The `docker-compose.yml` includes the Regula Face API service. Update the volume mount to point to your license file:

```yaml
regula-face-api:
  volumes:
    - ./local-secrets/regula.license:/app/extBin/unix/regula.license
```

Then start all services:

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

**Issue**: Face verification endpoints return "face verification not available"

**Solution**: Ensure the `regula_face_api_url` is configured in your `config.json` and the Regula Face API service is running. Check the service health:
```bash
curl http://localhost:41101/api/healthz
```
