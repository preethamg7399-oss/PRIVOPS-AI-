"""
Tests for Visual Privacy: Face Detection and Automatic Anonymization.
"""

import pytest
import cv2
import numpy as np
from backend.face_anonymizer import face_anonymizer_instance


def test_face_detector_initialization():
    assert face_anonymizer_instance.yunet_detector is not None


def test_blank_image_processing():
    # Blank image with no faces
    blank = np.zeros((300, 300, 3), dtype=np.uint8)
    success, buf = cv2.imencode(".png", blank)
    assert success is True

    prot_bytes, face_count, boxes, tele = face_anonymizer_instance.anonymize_image(
        image_bytes=buf.tobytes(),
        method="blur"
    )

    assert face_count == 0
    assert len(boxes) == 0
    assert len(prot_bytes) > 0
    assert tele["outbound_isolation"] == "100% Face Anonymized - Raw Biometrics Intercepted"


def test_synthetic_face_anonymization_methods():
    # Create image with simulated face features (skin oval + eye/mouth features)
    img = np.ones((400, 400, 3), dtype=np.uint8) * 240
    # Draw face oval
    cv2.ellipse(img, (200, 200), (80, 110), 0, 0, 360, (180, 210, 240), -1)
    # Eyes
    cv2.circle(img, (170, 170), 12, (50, 50, 50), -1)
    cv2.circle(img, (230, 170), 12, (50, 50, 50), -1)
    # Mouth
    cv2.ellipse(img, (200, 250), (35, 15), 0, 0, 180, (50, 50, 50), -1)

    success, buf = cv2.imencode(".png", img)
    raw_bytes = buf.tobytes()

    for method in ["blur", "pixelate", "mask"]:
        prot_bytes, count, boxes, tele = face_anonymizer_instance.anonymize_image(
            image_bytes=raw_bytes,
            method=method
        )
        assert len(prot_bytes) > 0
        assert tele["anonymization_method"] == method

