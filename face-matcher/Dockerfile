# Base images: Chainguard's Wolfi-based Python (glibc, minimal package set,
# rebuilt daily, no shell or package manager in the runtime variant). Chosen
# over python:*-slim because the Debian slims carry well over a hundred
# OS-level CVE findings (Trivy, 2026-09: python:3.13-slim-bookworm 251,
# python:3.13-slim-trixie 176, most of them unfixed upstream), which no Debian
# tag choice removes. The free Chainguard tier only publishes `latest`, so the
# Python minor version follows Chainguard; requirements.txt therefore avoids
# pins that only exist for one Python version.
#
# The runtime image has no pip or shell, so everything is installed into a
# venv in the -dev stage and the venv is copied over.

# ---------- Build stage: compile wheels into a venv ----------
FROM cgr.dev/chainguard/python:latest-dev AS build
USER root
# insightface ships a Cython extension; onnxruntime and opencv are wheels.
RUN apk add --no-cache build-base
WORKDIR /build
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Pre-download the model pack at build time so the container never reaches
# out at runtime.
ENV FACE_MATCHER_MODEL=buffalo_l \
    FACE_MATCHER_MODEL_ROOT=/models \
    MPLCONFIGDIR=/tmp/matplotlib
RUN python -c "from insightface.app import FaceAnalysis; \
    FaceAnalysis(name='${FACE_MATCHER_MODEL}', root='${FACE_MATCHER_MODEL_ROOT}', \
    providers=['CPUExecutionProvider'], allowed_modules=['detection','recognition']).prepare(ctx_id=-1)"
# The runtime image runs as uid 65532 (nonroot).
RUN chown -R 65532:65532 /venv /models

# ---------- Runtime: no shell, no package manager, non-root ----------
FROM cgr.dev/chainguard/python:latest
WORKDIR /app
COPY --from=build --chown=65532:65532 /venv /venv
COPY --from=build --chown=65532:65532 /models /models
COPY --chown=65532:65532 app.py .

ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    FACE_MATCHER_MODEL=buffalo_l \
    FACE_MATCHER_MODEL_ROOT=/models \
    MPLCONFIGDIR=/tmp/matplotlib

EXPOSE 8000
# No shell in the image: the health check is a Python one-liner. Compose or
# Kubernetes can probe GET /healthz directly instead.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"]
ENTRYPOINT ["python", "-m", "uvicorn", "app:create_default_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
