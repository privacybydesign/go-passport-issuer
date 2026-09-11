"""HTTP-layer tests for the face-matcher sidecar, run with a fake engine so no
model download or onnxruntime is needed: `pytest` in this directory."""

import base64
import io

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app import create_app, cosine_similarity


class FakeEngine:
    """Returns one canned embedding per face, keyed on the image's mean red.

    Images with mean red < 50 are treated as containing no face, >= 200 as two
    faces, anything else as one face whose embedding is the configured vector.
    """

    name = "fake"

    def __init__(self):
        self.embedding = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        self.seen_shapes = []

    def embed(self, image_bgr):
        self.seen_shapes.append(image_bgr.shape)
        mean_red = float(image_bgr[:, :, 2].mean())
        if mean_red < 50:
            return []
        if mean_red >= 200:
            return [self.embedding, self.embedding]
        return [self.embedding]


def encode(color=(120, 120, 120), size=(64, 64), fmt="PNG") -> str:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt)
    return base64.b64encode(buf.getvalue()).decode()


@pytest.fixture
def engine():
    return FakeEngine()


@pytest.fixture
def client(engine):
    return TestClient(create_app(engine))


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "model": "fake"}


def test_match_one_face_each_side(client):
    response = client.post("/match", json={"document_image": encode(), "live_image": encode()})
    assert response.status_code == 200
    body = response.json()
    assert body["document_faces"] == 1
    assert body["live_faces"] == 1
    assert body["similarity"] == pytest.approx(1.0)


def test_match_accepts_jpeg_document(client):
    response = client.post("/match", json={"document_image": encode(fmt="JPEG"), "live_image": encode()})
    assert response.status_code == 200
    assert response.json()["document_faces"] == 1


def test_images_reach_engine_as_bgr_arrays(client, engine):
    client.post("/match", json={"document_image": encode(size=(80, 60)), "live_image": encode(size=(64, 64))})
    assert engine.seen_shapes == [(60, 80, 3), (64, 64, 3)]


def test_no_face_in_document_reports_zero_similarity(client):
    response = client.post("/match", json={"document_image": encode(color=(10, 10, 10)), "live_image": encode()})
    assert response.status_code == 200
    body = response.json()
    assert body["document_faces"] == 0
    assert body["live_faces"] == 1
    assert body["similarity"] == 0.0


def test_two_faces_in_live_image_reports_count_and_zero_similarity(client):
    response = client.post("/match", json={"document_image": encode(), "live_image": encode(color=(250, 120, 120))})
    assert response.status_code == 200
    body = response.json()
    assert body["live_faces"] == 2
    assert body["similarity"] == 0.0


def test_invalid_base64_is_422(client):
    response = client.post("/match", json={"document_image": "@@@", "live_image": encode()})
    assert response.status_code == 422
    assert "document_image" in response.json()["detail"]


def test_undecodable_image_is_422(client):
    garbage = base64.b64encode(b"definitely not an image").decode()
    response = client.post("/match", json={"document_image": encode(), "live_image": garbage})
    assert response.status_code == 422
    assert "live_image" in response.json()["detail"]


def test_empty_image_is_422(client):
    response = client.post("/match", json={"document_image": "", "live_image": encode()})
    assert response.status_code == 422


def test_missing_field_is_422(client):
    response = client.post("/match", json={"document_image": encode()})
    assert response.status_code == 422


def test_cosine_similarity():
    a = np.array([1.0, 0.0])
    assert cosine_similarity(a, a) == pytest.approx(1.0)
    assert cosine_similarity(a, np.array([0.0, 1.0])) == pytest.approx(0.0)
    assert cosine_similarity(a, np.array([-1.0, 0.0])) == pytest.approx(-1.0)
    assert cosine_similarity(a, np.zeros(2)) == 0.0
    # Small nonzero embeddings still have a well-defined cosine similarity.
    tiny = np.array([1e-12, 0.0])
    assert cosine_similarity(tiny, tiny) == pytest.approx(1.0)
