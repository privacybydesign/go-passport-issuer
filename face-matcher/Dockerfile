# Base images: Chainguard's Wolfi-based Python (glibc, minimal package set,
# rebuilt daily, no shell or package manager in the runtime variant). Chosen
# over python:*-slim because the Debian slims carry well over a hundred
# OS-level CVE findings (Trivy, 2026-09: python:3.13-slim-bookworm 251,
# python:3.13-slim-trixie 176, most of them unfixed upstream), which no Debian
# tag choice removes. Both stages are pinned by digest; update them together
# with the dependency locks to keep the Python ABI aligned.
#
# The runtime image has no pip or shell, so everything is installed into a
# venv in the -dev stage and the venv is copied over.

# ---------- Build stage: compile wheels into a venv ----------
FROM cgr.dev/chainguard/python@sha256:df9eb3812f118b33f8fd0bafb7efa0112d6a0810b40b2707337a4c432845f7b4 AS build
USER root
# insightface ships a Cython extension; onnxruntime and opencv are wheels.
RUN apk add --no-cache build-base
WORKDIR /build
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"
COPY requirements-build.lock requirements.lock ./
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-build.lock
# InsightFace 0.7.3 is source-only. Allow only this hash-verified release to
# compile its Cython extension, using the locked build tools above. Disable
# build isolation so pip cannot fetch unpinned build dependencies.
RUN pip install --no-cache-dir --only-binary=:all: --no-binary=insightface \
    --require-hashes --no-build-isolation -r requirements.lock

# Pre-download the model pack at build time so the container never reaches
# out at runtime.
ENV FACE_MATCHER_MODEL=buffalo_l \
    FACE_MATCHER_MODEL_ROOT=/models \
    MPLCONFIGDIR=/tmp/matplotlib
RUN python -c "from insightface.app import FaceAnalysis; \
    FaceAnalysis(name='${FACE_MATCHER_MODEL}', root='${FACE_MATCHER_MODEL_ROOT}', \
    providers=['CPUExecutionProvider'], allowed_modules=['detection','recognition']).prepare(ctx_id=-1)"

# ---------- Runtime: no shell, no package manager, non-root ----------
FROM cgr.dev/chainguard/python@sha256:780029a86e72bf3a58b1795cb77ab73b8f48dfea8c94ab154345396dc3d3237a
USER root
WORKDIR /app
# Apply read/execute-only permissions while copying, avoiding a recursive
# metadata update that duplicates the large model and dependency layers.
COPY --from=build --chown=0:0 --chmod=0555 /venv /venv
COPY --from=build --chown=0:0 --chmod=0555 /models /models
COPY --chown=0:0 --chmod=0444 app.py .
USER 65532:65532

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
