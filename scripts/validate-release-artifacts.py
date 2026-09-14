#!/usr/bin/env python3
"""Validate release dependencies against a reviewed, repository-owned lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path


ARCHITECTURES = ("amd64", "arm64")
COMPONENT_NAMES = (
    "awg",
    "awg-quick",
    "amneziawg-go",
    "hev-socks5-tunnel",
    "lego",
)
COMPONENT_FILES = {
    "BUILD-METADATA.json",
    "SHA256SUMS",
    "THIRD_PARTY_NOTICES.md",
    "licenses/amneziawg-go-LICENSE",
    "licenses/amneziawg-tools-COPYING",
    "licenses/hev-socks5-tunnel-LICENSE",
    "licenses/lego-LICENSE",
    "source/amneziawg-tools-source.tar.gz",
    *(f"{architecture}/{name}" for architecture in ARCHITECTURES for name in COMPONENT_NAMES),
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s]+)$")


class ValidationError(RuntimeError):
    pass


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file_inventory(root: Path) -> set[str]:
    observed: set[str] = set()
    if not root.is_dir() or root.is_symlink():
        raise ValidationError(f"Artifact directory is missing or unsafe: {root}")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValidationError(f"Artifact inventory contains a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValidationError(f"Artifact inventory contains an unsupported file: {path}")
        relative = path.relative_to(root).as_posix()
        if relative.startswith("/") or ".." in Path(relative).parts:
            raise ValidationError("Artifact inventory contains an unsafe path")
        observed.add(relative)
    return observed


def read_json(path: Path, *, maximum: int = 1024 * 1024) -> object:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise ValidationError(f"JSON input is missing, unsafe, or too large: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"JSON input is invalid: {path}") from exc


def validate_hash_mapping(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ValidationError(f"{label} must be a non-empty filename-to-SHA-256 object")
    result: dict[str, str] = {}
    for filename, digest in value.items():
        if (
            not isinstance(filename, str)
            or not filename
            or filename.startswith("/")
            or ".." in Path(filename).parts
            or not isinstance(digest, str)
            or not SHA256_PATTERN.fullmatch(digest)
        ):
            raise ValidationError(f"{label} contains an unsafe filename or invalid SHA-256")
        result[filename] = digest
    return result


def read_requirements(path: Path) -> dict[str, tuple[str, str]]:
    if not path.is_file() or path.is_symlink():
        raise ValidationError("requirements.lock is missing or unsafe")
    requirements: dict[str, tuple[str, str]] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_PATTERN.fullmatch(line)
        if not match:
            raise ValidationError(
                f"requirements.lock line {line_number} is not an exact name==version pin"
            )
        canonical = normalized_name(match.group(1))
        if canonical in requirements:
            raise ValidationError(f"requirements.lock contains duplicate package {canonical}")
        requirements[canonical] = (match.group(1), match.group(2))
    if not requirements:
        raise ValidationError("requirements.lock is empty")
    return requirements


def wheel_identity(path: Path) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_members = []
            for member in archive.infolist():
                member_path = Path(member.filename)
                mode = member.external_attr >> 16
                if (
                    member.filename.startswith("/")
                    or ".." in member_path.parts
                    or stat.S_ISLNK(mode)
                ):
                    raise ValidationError(f"Wheel contains an unsafe member: {path.name}")
                if member.filename.endswith(".dist-info/METADATA"):
                    metadata_members.append(member)
            if len(metadata_members) != 1:
                raise ValidationError(f"Wheel has an invalid METADATA inventory: {path.name}")
            member = metadata_members[0]
            if member.file_size > 1024 * 1024:
                raise ValidationError(f"Wheel METADATA is unexpectedly large: {path.name}")
            metadata = Parser().parsestr(archive.read(member).decode("utf-8"))
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise ValidationError(f"Wheel is unreadable: {path.name}") from exc
    name = metadata.get("Name", "")
    version = metadata.get("Version", "")
    if not name or not version:
        raise ValidationError(f"Wheel metadata is missing Name or Version: {path.name}")
    return normalized_name(name), version


def validate_wheel_architecture(filename: str, architecture: str) -> None:
    if not filename.endswith(".whl"):
        raise ValidationError(f"Wheelhouse contains a non-wheel file: {filename}")
    fields = filename[:-4].split("-")
    if (
        len(fields) not in {5, 6}
        or not all(fields)
        or (len(fields) == 6 and not re.fullmatch(r"[0-9][A-Za-z0-9_]*", fields[2]))
        or not all(re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_]+)*", tag) for tag in fields[-3:])
    ):
        raise ValidationError(f"Wheel filename is malformed: {filename}")

    # Validate the target, not the builder's OS/interpreter. A substring match
    # also accepts Windows wheels and CPython 3.13-only ARM64 wheels, which the
    # amd64 signing preflight cannot discover by installing its own wheelhouse.
    # Keep this standalone: validation runs before release dependencies exist.
    machine = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
    platforms = {f"manylinux_2_{minor}_{machine}" for minor in range(17, 40)}
    platforms.add(f"manylinux2014_{machine}")
    if architecture == "amd64":
        platforms.update({f"manylinux1_{machine}", f"manylinux2010_{machine}"})
        platforms.update(f"manylinux_2_{minor}_{machine}" for minor in range(5, 17))

    supported = {("cp312", abi, platform) for abi in ("cp312", "none") for platform in platforms}
    supported.update(
        (f"cp3{minor}", "abi3", platform)
        for minor in range(2, 13)
        for platform in platforms
    )
    generic_python = {"py3", *(f"py3{minor}" for minor in range(13))}
    supported.update(
        (python, "none", platform)
        for python in generic_python
        for platform in platforms | {"any"}
    )
    supported.add(("cp312", "none", "any"))
    python_tags, abi_tags, platform_tags = (field.split(".") for field in fields[-3:])
    if not any(
        (python, abi, platform) in supported
        for python in python_tags
        for abi in abi_tags
        for platform in platform_tags
    ):
        raise ValidationError(
            f"Wheel {filename} is not compatible with Ubuntu 24.04 CPython 3.12 {architecture}"
        )


def validate_wheelhouses(
    lock: dict[str, object],
    wheelhouse: Path,
    requirements: dict[str, tuple[str, str]],
) -> None:
    locked = lock.get("wheelhouses")
    if not isinstance(locked, dict) or set(locked) != set(ARCHITECTURES):
        raise ValidationError("Artifact lock must contain exactly amd64 and arm64 wheelhouses")
    for architecture in ARCHITECTURES:
        item = locked[architecture]
        if not isinstance(item, dict) or set(item) != {"files"}:
            raise ValidationError(f"Artifact lock {architecture} wheelhouse has an invalid format")
        expected = validate_hash_mapping(item["files"], f"{architecture} wheelhouse")
        root = wheelhouse / architecture
        observed = regular_file_inventory(root)
        if observed != set(expected):
            raise ValidationError(
                f"{architecture} wheelhouse does not exactly match the reviewed artifact lock"
            )
        packages: dict[str, str] = {}
        for filename, digest in expected.items():
            validate_wheel_architecture(filename, architecture)
            path = root / filename
            if sha256(path) != digest:
                raise ValidationError(
                    f"{architecture} wheel failed its reviewed SHA-256: {filename}"
                )
            name, version = wheel_identity(path)
            if name in packages:
                raise ValidationError(
                    f"{architecture} wheelhouse contains duplicate package {name}"
                )
            packages[name] = version
        expected_packages = {name: version for name, (_display, version) in requirements.items()}
        if packages != expected_packages:
            raise ValidationError(
                f"{architecture} wheel package names or versions do not match requirements.lock"
            )


def validate_components(lock: dict[str, object], component_root: Path) -> dict[str, str]:
    value = lock.get("components")
    if not isinstance(value, dict) or set(value) != {"files", "build_metadata"}:
        raise ValidationError("Artifact lock component section has an invalid format")
    expected = validate_hash_mapping(value["files"], "component bundle")
    if set(expected) != COMPONENT_FILES:
        raise ValidationError(
            "Artifact lock component inventory does not match CayVPN's required files"
        )
    observed = regular_file_inventory(component_root)
    if observed != set(expected):
        raise ValidationError(
            "Optional-component bundle does not exactly match the reviewed artifact lock"
        )
    for filename, digest in expected.items():
        if sha256(component_root / filename) != digest:
            raise ValidationError(
                f"Optional component failed its reviewed SHA-256: {filename}"
            )
    actual_metadata = read_json(component_root / "BUILD-METADATA.json")
    if actual_metadata != value["build_metadata"]:
        raise ValidationError(
            "Optional-component source versions do not match the reviewed artifact lock"
        )
    return expected


def validate_lock(
    lock_path: Path,
    requirements_path: Path,
    wheelhouse: Path,
    components: Path,
    release_version: str,
) -> tuple[dict[str, object], dict[str, str]]:
    document = read_json(lock_path)
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "release_version",
            "python_version",
            "requirements_sha256",
            "wheelhouses",
            "components",
        }
        or document.get("schema_version") != 1
        or document.get("release_version") != release_version
        or document.get("python_version") != "3.12"
        or not isinstance(document.get("requirements_sha256"), str)
        or not SHA256_PATTERN.fullmatch(document["requirements_sha256"])
    ):
        raise ValidationError("Reviewed release artifact lock has an invalid format or version")
    if sha256(requirements_path) != document["requirements_sha256"]:
        raise ValidationError("requirements.lock does not match the reviewed release artifact lock")
    requirements = read_requirements(requirements_path)
    validate_wheelhouses(document, wheelhouse, requirements)
    component_hashes = validate_components(document, components)
    return document, component_hashes


def write_component_lock(
    destination: Path, release_version: str, component_hashes: dict[str, str]
) -> None:
    document = {
        "schema_version": 1,
        "release_version": release_version,
        "architectures": {
            architecture: {
                name: {
                    "path": f"components/{architecture}/{name}",
                    "sha256": component_hashes[f"{architecture}/{name}"],
                }
                for name in COMPONENT_NAMES
            }
            for architecture in ARCHITECTURES
        },
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--write-component-lock", type=Path)
    arguments = parser.parse_args()
    try:
        _document, component_hashes = validate_lock(
            arguments.lock,
            arguments.requirements,
            arguments.wheelhouse,
            arguments.components,
            arguments.release_version,
        )
        if arguments.write_component_lock:
            write_component_lock(
                arguments.write_component_lock,
                arguments.release_version,
                component_hashes,
            )
    except (OSError, ValidationError) as exc:
        print(f"Release artifact validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        "Validated wheelhouses and native components against the reviewed release artifact lock",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
