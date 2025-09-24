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

After the backend is running, the API documentation is available at `http://localhost:8080/docs`.

### Updating API documentation

The OpenAPI description served at `/openapi.yaml` is generated from inline annotations.
Run the following command from the `backend` directory whenever the handlers change:

```bash
go generate ./...
```

This command downloads the [`swag`](https://github.com/swaggo/swag) generator (if not already cached) and refreshes the files under `backend/docs/`.

To run the frontend, navigate to the `frontend` directory and execute:
```bash
npm install
npm start
``` 

To run both the backend and frontend using Docker Compose, ensure you have Docker and Docker Compose installed. Then, from the root directory of the project, execute:
```bash
docker-compose up --build
```
