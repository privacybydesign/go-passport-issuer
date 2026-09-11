"""face-matcher: self-hosted 1:1 face matching sidecar for go-passport-issuer.

Variant B of face verification (on-device Iris SDK) hands the issuer the live
face crop the SDK captured. The issuer does not trust the device's verdict and
re-matches that crop against the document chip portrait here, with an
open-source ArcFace model (InsightFace) that we run ourselves. Nothing in this
service talks to Regula or to any external party.

API
    GET  /healthz                 -> {"status": "ok", "model": "<name>"}
    POST /match                   -> {"similarity": float, "document_faces": int, "live_faces": int}
         {"document_image": "<base64>", "live_image": "<base64>"}

Images are raw encoded bytes (PNG, JPEG or JPEG 2000 as stored in DG2/DG6),
base64 encoded for transport. Nothing is written to disk; the request is the
only place the images ever live.

`similarity` is the cosine similarity between the two normalised embeddings,
reported only when exactly one face was found in each image (0.0 otherwise).
Deciding whether that similarity is a match is the issuer's job (its
configured threshold); this service only reports what it saw.
"""

from __future__ import annotations

import base64
import io
import logging
import os
from typing import Protocol, Sequence

import numpy as np
from fastapi import FastAPI, HTTPException
from PIL import Image
from pydantic import BaseModel

log = logging.getLogger("face-matcher")

# Largest decoded image accepted per side. The issuer already caps the live
# crop at 2 MiB; the document portrait is a DG2 image of a few tens of kB.
MAX_IMAGE_BYTES = int(os.environ.get("FACE_MATCHER_MAX_IMAGE_BYTES", str(4 * 1024 * 1024)))
MODEL_NAME = os.environ.get("FACE_MATCHER_MODEL", "buffalo_l")
# Where InsightFace keeps its downloaded model packs. The Dockerfile pre-fills
# this at build time so the container never downloads at runtime.
MODEL_ROOT = os.environ.get("FACE_MATCHER_MODEL_ROOT", os.path.expanduser("~/.insightface"))


class Engine(Protocol):
    """Turns an image into one embedding per detected face."""

    name: str

    def embed(self, image_bgr: np.ndarray) -> Sequence[np.ndarray]: ...


class InsightFaceEngine:
    """ArcFace embeddings via InsightFace's FaceAnalysis pipeline (CPU)."""

    def __init__(self, model_name: str = MODEL_NAME, model_root: str = MODEL_ROOT, det_size: tuple[int, int] = (640, 640)):
        # Imported lazily so the HTTP layer can be tested without the heavy
        # onnxruntime / insightface stack installed.
        from insightface.app import FaceAnalysis

        self.name = model_name
        self._app = FaceAnalysis(
            name=model_name,
            root=model_root,
            providers=["CPUExecutionProvider"],
            allowed_modules=["detection", "recognition"],
        )
        self._app.prepare(ctx_id=-1, det_size=det_size)

    def embed(self, image_bgr: np.ndarray) -> Sequence[np.ndarray]:
        return [face.normed_embedding for face in self._app.get(image_bgr)]


def decode_image(field: str, encoded: str) -> np.ndarray:
    """Base64 -> BGR uint8 array, or a 422 naming the offending field."""
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{field} is not valid base64")
    if not data:
        raise HTTPException(status_code=422, detail=f"{field} is empty")
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=422, detail=f"{field} exceeds {MAX_IMAGE_BYTES} bytes")

    try:
        with Image.open(io.BytesIO(data)) as img:
            rgb = np.asarray(img.convert("RGB"))
    except (OSError, ValueError):
        raise HTTPException(status_code=422, detail=f"{field} could not be decoded as an image")

    # InsightFace, like OpenCV, expects BGR channel order.
    return np.ascontiguousarray(rgb[:, :, ::-1])


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denominator = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denominator <= 0.0:
        return 0.0
    return float(np.dot(a, b) / denominator)


class MatchRequest(BaseModel):
    document_image: str
    live_image: str


class MatchResponse(BaseModel):
    similarity: float
    document_faces: int
    live_faces: int


def create_app(engine: Engine) -> FastAPI:
    app = FastAPI(title="face-matcher", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "model": engine.name}

    @app.post("/match", responses={422: {"description": "Invalid request or empty, oversized, or undecodable image"}})
    def match(request: MatchRequest) -> MatchResponse:
        document = decode_image("document_image", request.document_image)
        live = decode_image("live_image", request.live_image)

        document_embeddings = engine.embed(document)
        live_embeddings = engine.embed(live)

        similarity = 0.0
        if len(document_embeddings) == 1 and len(live_embeddings) == 1:
            similarity = cosine_similarity(document_embeddings[0], live_embeddings[0])

        # Never log image content; counts and the score are all that is needed
        # to analyse the experiment.
        log.info(
            "match similarity=%.4f document_faces=%d live_faces=%d",
            similarity,
            len(document_embeddings),
            len(live_embeddings),
        )
        return MatchResponse(
            similarity=similarity,
            document_faces=len(document_embeddings),
            live_faces=len(live_embeddings),
        )

    return app


def create_default_app() -> FastAPI:
    """Uvicorn factory entry point: `uvicorn app:create_default_app --factory`."""
    logging.basicConfig(level=os.environ.get("FACE_MATCHER_LOG_LEVEL", "INFO"))
    return create_app(InsightFaceEngine())
