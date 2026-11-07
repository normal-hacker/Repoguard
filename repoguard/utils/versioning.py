"""Versioning helpers and SemVer validation."""

from __future__ import annotations

import re
from typing import NamedTuple

SEMVER_REGEX = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


class SemVer(NamedTuple):
    major: int
    minor: int
    patch: int
    prerelease: str | None = None
    buildmetadata: str | None = None

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base = f"{base}-{self.prerelease}"
        if self.buildmetadata:
            base = f"{base}+{self.buildmetadata}"
        return base


def parse_semver(version_str: str) -> SemVer | None:
    """Parse a semantic version string. Returns SemVer or None if invalid."""
    match = SEMVER_REGEX.match(version_str.strip())
    if not match:
        return None
    data = match.groupdict()
    return SemVer(
        major=int(data["major"]),
        minor=int(data["minor"]),
        patch=int(data["patch"]),
        prerelease=data.get("prerelease"),
        buildmetadata=data.get("buildmetadata"),
    )


def is_valid_semver(version_str: str) -> bool:
    """Return True if version_str matches the SemVer 2.0.0 specification."""
    return parse_semver(version_str) is not None
