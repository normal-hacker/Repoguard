"""Tests for versioning and SemVer utilities."""

from __future__ import annotations

import pytest

from repoguard.utils.versioning import SemVer, is_valid_semver, parse_semver


@pytest.mark.parametrize(
    "version_str, expected",
    [
        ("1.0.0", SemVer(1, 0, 0)),
        ("0.1.0", SemVer(0, 1, 0)),
        ("2.14.3", SemVer(2, 14, 3)),
        ("1.0.0-alpha.1", SemVer(1, 0, 0, prerelease="alpha.1")),
        ("1.0.0+20130313144700", SemVer(1, 0, 0, buildmetadata="20130313144700")),
        (
            "1.0.0-beta.2+exp.sha.5114f85",
            SemVer(1, 0, 0, prerelease="beta.2", buildmetadata="exp.sha.5114f85"),
        ),
    ],
)
def test_parse_semver_valid(version_str: str, expected: SemVer) -> None:
    result = parse_semver(version_str)
    assert result is not None
    assert result == expected
    assert is_valid_semver(version_str) is True


@pytest.mark.parametrize(
    "invalid_version",
    [
        "1",
        "1.0",
        "v1.0.0",
        "1.0.0.0",
        "alpha.1",
        "1.0.0-01",
        "",
        "not-a-version",
    ],
)
def test_parse_semver_invalid(invalid_version: str) -> None:
    assert parse_semver(invalid_version) is None
    assert is_valid_semver(invalid_version) is False
