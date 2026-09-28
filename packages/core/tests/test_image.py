"""Tests for the Image dataclass."""

from datetime import datetime, timezone

from oke_scanner_core.image import Image


def test_parse_image_with_registry_and_tag():
    """Test parsing image with explicit registry and tag."""
    image = Image("iad.ocir.io/namespace/repo:v1.0.0")

    assert image.registry == "iad.ocir.io"
    assert image.repo_name == "namespace/repo"
    assert image.tag == "v1.0.0"
    assert image.full_name == "iad.ocir.io/namespace/repo:v1.0.0"


def test_parse_image_with_latest_tag():
    """Test parsing image with latest tag."""
    image = Image("docker.io/library/nginx:latest")

    assert image.registry == "docker.io"
    assert image.repo_name == "library/nginx"
    assert image.tag == "latest"


def test_parse_image_strips_digest():
    """Test parsing image with digest (@sha256:...) strips it from tag."""
    image = Image("registry.k8s.io/ingress-nginx/controller:v1.14.3@sha256:abc123def456")

    assert image.registry == "registry.k8s.io"
    assert image.repo_name == "ingress-nginx/controller"
    assert image.tag == "v1.14.3"


def test_is_ocir_image():
    """Test is_ocir_image property."""
    ocir_image = Image("iad.ocir.io/namespace/repo:v1.0.0")
    docker_image = Image("docker.io/library/nginx:latest")

    assert ocir_image.is_ocir_image is True
    assert docker_image.is_ocir_image is False


def test_image_comparison_with_created_at():
    """Test Image comparison uses created_at when present."""
    img1 = Image("registry.io/repo:abc1234", created_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
    img2 = Image("registry.io/repo:def5678", created_at=datetime(2024, 2, 1, tzinfo=timezone.utc))

    assert img1 < img2
    assert img2 > img1


def test_image_comparison_falls_back_to_full_name():
    """Test Image comparison falls back to full_name when created_at missing."""
    img1 = Image("registry.io/repo:a")
    img2 = Image("registry.io/repo:b")

    assert img1 < img2


def test_image_equality_compares_full_name():
    """Two Images with the same full_name are equal even with different metadata."""
    img1 = Image("registry.io/repo:a", ocid="ocid1")
    img2 = Image("registry.io/repo:a", ocid="ocid2")
    img3 = Image("registry.io/repo:b")

    assert img1 == img2
    assert img1 != img3


def test_image_str_returns_full_name():
    """str(Image) returns the full image reference."""
    image = Image("registry.io/repo:a")

    assert str(image) == "registry.io/repo:a"
