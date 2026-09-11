# face-matcher

Self-hosted 1:1 face matching sidecar for the passport issuer. It backs
**variant B** of face verification (on-device Iris SDK): the app sends the
issuer the live face crop the SDK captured, and the issuer re-matches that crop
against the document chip portrait here instead of trusting the device's
verdict. The model is open source (InsightFace ArcFace, `buffalo_l` pack) and
runs on CPU inside our own infrastructure. Regula is not involved.

## API

| Endpoint | Body | Response |
|---|---|---|
| `GET /healthz` | – | `{"status":"ok","model":"buffalo_l"}` |
| `POST /match` | `{"document_image":"<base64>","live_image":"<base64>"}` | `{"similarity":0.63,"document_faces":1,"live_faces":1}` |

Images are raw encoded bytes (PNG, JPEG, or the JPEG 2000 found in DG2/DG6),
base64 for transport. `similarity` is the cosine similarity of the two
normalised embeddings and is only computed when exactly one face is detected
on each side; otherwise it is `0.0` and the counts say why. Malformed input is
a `422` naming the field. Nothing is stored and image content is never logged.

The **threshold** lives in the issuer (`face_matcher_threshold`), not here.
ArcFace cosine similarities are on a different scale than Regula's 0 to 1
score, so calibrate it on a labelled set of chip portraits and live crops
before relying on it. The issuer logs the similarity of every B session, which
produces that set over time.

## Run

Through the repository's `docker-compose.yml` (`face-matcher` service, port
8000 on the internal network), or standalone:

```bash
docker build -t face-matcher .
docker run --rm -p 8000:8000 face-matcher
```

The model pack (about 280 MB) is downloaded at image build time and baked in;
the container makes no network calls at runtime.

### Base image

The image is built on Chainguard's Wolfi-based Python images
(`cgr.dev/chainguard/python`, with build and runtime digests pinned). The
runtime variant has no shell or package manager and runs as a non-root user,
and Chainguard rebuilds it daily against upstream fixes. This was chosen after
scanning the alternatives with Trivy (September 2026):

| Base | OS-level findings |
|---|---|
| `python:3.13-slim-bookworm` (Debian 12) | 251 (5 critical) |
| `python:3.13-slim-trixie` / `python:3.11-slim` (Debian 13) | 176 (3 critical) |
| `cgr.dev/chainguard/python:latest` | not measured here (scan blocked by a full disk); Chainguard publishes per-image counts at images.chainguard.dev |

Most Debian findings are unfixed upstream, so no Debian tag removes them. The
free Chainguard tier only publishes moving tags, so the Dockerfile pins both
images by digest. Update both digests together and regenerate the dependency
locks with the new build image's Python version.

### Dependency locks

The image installs `requirements.lock` and `requirements-build.lock`, which
pin all resolved versions and verify distribution hashes. All dependencies
must have wheels except InsightFace 0.7.3, whose hash-verified source release
compiles a Cython extension in the build stage. Build isolation is disabled
so its build tools come exclusively from the build lock. Source builds for
other packages fail instead of silently executing their setup scripts.

To regenerate the locks, run these commands from this directory inside the
pinned build image with uv 0.12.13 installed in a temporary virtual environment:

```bash
uv pip compile requirements.txt --generate-hashes --output-file requirements.lock
uv pip compile requirements-build.txt --constraint requirements.lock --generate-hashes --output-file requirements-build.lock
```

Rebuild the image after each update to verify wheel availability and the
InsightFace extension. Runtime code, dependencies, and models are root-owned
and cannot be modified by the non-root service user.

The remaining vulnerability surface is the Python dependency set
(onnxruntime, OpenCV, InsightFace); scan the built image, not just the base:

```bash
docker run --rm -v trivy-cache:/root/.cache/ -v //var/run/docker.sock:/var/run/docker.sock   aquasec/trivy image --scanners vuln face-matcher
```

Issuer config:

```json
"face_matcher_url": "http://face-matcher:8000",
"face_matcher_threshold": 0.4
```

## Test

The HTTP layer is tested with a fake engine, so no model or onnxruntime is
needed:

```bash
python -m venv .venv && . .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt
pytest
```

## Layout

- `app.py`: FastAPI app, `Engine` protocol, `InsightFaceEngine`, image decoding.
- `test_app.py`: HTTP tests against `FakeEngine`.
- `requirements.txt` / `requirements-dev.txt`: runtime vs test dependencies.
- `requirements-build.txt`: source-build tools; `*.lock`: hashed deployment dependencies.
