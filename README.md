[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=privacybydesign_go-passport-issuer&metric=coverage)](https://sonarcloud.io/summary/new_code?id=privacybydesign_go-passport-issuer)
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
    "jwt_private_key_path": "../local-secrets/passport-issuer/private.pem",
    "issuer_id": "passport_issuer",
    "full_credential": "pbdf-staging.pbdf.passport",
    "storage_type": "memory"
}
```
The `jwt_private_key_path` should point to a valid RSA private key in PEM format, which is used to sign JWT tokens for the IRMA server.

### Running the application

To run the backend server, ensure you have Go installed and set up on your machine. Navigate to the `go-passport-issuer` directory and execute the following command:
```bash
go run . --config ../local-secrets/config.json
```

To run the frontend, navigate to the `frontend` directory and execute:
```bash
npm install
npm start
``` 

To run both the backend and frontend using Docker Compose, ensure you have Docker and Docker Compose installed. Then, from the root directory of the project, execute:
```bash
docker-compose up --build
```
