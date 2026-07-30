#!/usr/bin/env python3
"""Verify a signed Maven Central deployment bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
import zipfile


CHECKSUMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


class VerificationError(Exception):
    """Raised when the deployment bundle violates a release invariant."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("public_key", type=Path)
    parser.add_argument("expected_fingerprint")
    parser.add_argument(
        "--properties",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "gradle.properties",
    )
    parser.add_argument("--artifact", default="akdanmaku")
    return parser.parse_args()


def read_properties(path: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        properties[name.strip()] = value.strip()
    return properties


def require_property(properties: dict[str, str], name: str) -> str:
    value = properties.get(name)
    if not value:
        raise VerificationError(f"missing Gradle property: {name}")
    return value


def expected_bundle_files(
    group: str,
    artifact: str,
    version: str,
) -> tuple[str, list[str], set[str]]:
    coordinate_path = f"{group.replace('.', '/')}/{artifact}/{version}"
    prefix = f"{artifact}-{version}"
    artifacts = [
        f"{prefix}.aar",
        f"{prefix}.pom",
        f"{prefix}-sources.jar",
        f"{prefix}-javadoc.jar",
    ]
    expected: set[str] = set()
    for filename in artifacts:
        path = f"{coordinate_path}/{filename}"
        expected.add(path)
        expected.add(f"{path}.asc")
        expected.update(f"{path}.{algorithm}" for algorithm in CHECKSUMS)
    return coordinate_path, artifacts, expected


def verify_archive_entries(
    archive: zipfile.ZipFile,
    expected: set[str],
) -> None:
    actual = {info.filename for info in archive.infolist() if not info.is_dir()}
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append(f"missing files: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected files: {', '.join(unexpected)}")
        raise VerificationError("; ".join(details))


def verify_checksums(directory: Path, artifacts: list[str]) -> None:
    for filename in artifacts:
        artifact = directory / filename
        content = artifact.read_bytes()
        for suffix, digest_factory in CHECKSUMS.items():
            expected = (directory / f"{filename}.{suffix}").read_text(
                encoding="ascii"
            ).strip().lower()
            actual = digest_factory(content).hexdigest()
            if actual != expected:
                raise VerificationError(
                    f"{suffix} mismatch for {artifact.name}: "
                    f"expected {expected}, got {actual}"
                )


def verify_archives(directory: Path, artifact: str, version: str) -> None:
    archive_names = [
        f"{artifact}-{version}.aar",
        f"{artifact}-{version}-sources.jar",
        f"{artifact}-{version}-javadoc.jar",
    ]
    for name in archive_names:
        path = directory / name
        try:
            with zipfile.ZipFile(path) as archive:
                files = [info for info in archive.infolist() if not info.is_dir()]
                if not files:
                    raise VerificationError(f"archive is empty: {name}")
        except zipfile.BadZipFile as error:
            raise VerificationError(f"invalid ZIP archive: {name}") from error


def find_text(root: ElementTree.Element, path: str) -> str:
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    value = root.findtext(path, namespaces=namespace)
    return value.strip() if value else ""


def verify_pom(
    pom: Path,
    properties: dict[str, str],
    artifact: str,
) -> None:
    try:
        root = ElementTree.parse(pom).getroot()
    except ElementTree.ParseError as error:
        raise VerificationError(f"invalid POM XML: {error}") from error

    expected = {
        "m:groupId": require_property(properties, "GROUP"),
        "m:artifactId": artifact,
        "m:version": require_property(properties, "VERSION_NAME"),
        "m:packaging": "aar",
        "m:name": "AkDanmaku",
        "m:url": require_property(properties, "POM_URL"),
        "m:licenses/m:license/m:name": require_property(
            properties, "POM_LICENCE_NAME"
        ),
        "m:licenses/m:license/m:url": require_property(
            properties, "POM_LICENCE_URL"
        ),
        "m:developers/m:developer/m:id": require_property(
            properties, "POM_DEVELOPER_ID"
        ),
        "m:developers/m:developer/m:name": require_property(
            properties, "POM_DEVELOPER_NAME"
        ),
        "m:scm/m:connection": require_property(
            properties, "POM_SCM_CONNECTION"
        ),
        "m:scm/m:developerConnection": require_property(
            properties, "POM_SCM_DEV_CONNECTION"
        ),
        "m:scm/m:url": require_property(properties, "POM_SCM_URL"),
    }
    if not find_text(root, "m:description"):
        raise VerificationError("POM metadata is missing a description")
    mismatches = [
        f"{path}: expected {value!r}, got {find_text(root, path)!r}"
        for path, value in expected.items()
        if find_text(root, path) != value
    ]
    if mismatches:
        raise VerificationError("POM metadata mismatch: " + "; ".join(mismatches))


def verify_signatures(
    directory: Path,
    artifacts: list[str],
    public_key: Path,
    expected_fingerprint: str,
) -> None:
    if shutil.which("gpg") is None:
        raise VerificationError("gpg is required to verify signatures")

    with tempfile.TemporaryDirectory(prefix="akdanmaku-gpg-") as home:
        gpg_home = Path(home)
        os.chmod(gpg_home, 0o700)
        imported = subprocess.run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(gpg_home),
                "--import",
                str(public_key),
            ],
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            raise VerificationError(
                f"failed to import verification key: {imported.stderr.strip()}"
            )

        expected_fingerprint = expected_fingerprint.upper()
        for filename in artifacts:
            artifact = directory / filename
            signature = directory / f"{filename}.asc"
            if not signature.read_text(encoding="ascii").startswith(
                "-----BEGIN PGP SIGNATURE-----"
            ):
                raise VerificationError(
                    f"signature is not ASCII-armored: {signature.name}"
                )
            verified = subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--homedir",
                    str(gpg_home),
                    "--status-fd",
                    "1",
                    "--verify",
                    str(signature),
                    str(artifact),
                ],
                capture_output=True,
                text=True,
            )
            if verified.returncode != 0:
                raise VerificationError(
                    f"invalid signature for {filename}: {verified.stderr.strip()}"
                )
            valid_fingerprints = {
                line.split()[2].upper()
                for line in verified.stdout.splitlines()
                if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) > 2
            }
            if expected_fingerprint not in valid_fingerprints:
                raise VerificationError(
                    f"unexpected signing key for {filename}: "
                    f"{', '.join(sorted(valid_fingerprints)) or 'none'}"
                )


def verify(args: argparse.Namespace) -> None:
    if not args.bundle.is_file():
        raise VerificationError(f"bundle does not exist: {args.bundle}")
    if not args.public_key.is_file():
        raise VerificationError(f"public key does not exist: {args.public_key}")

    properties = read_properties(args.properties)
    group = require_property(properties, "GROUP")
    version = require_property(properties, "VERSION_NAME")
    coordinate_path, artifacts, expected = expected_bundle_files(
        group,
        args.artifact,
        version,
    )

    with tempfile.TemporaryDirectory(prefix="akdanmaku-bundle-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(args.bundle) as archive:
            verify_archive_entries(archive, expected)
            archive.extractall(root)

        directory = root / coordinate_path
        verify_checksums(directory, artifacts)
        verify_archives(directory, args.artifact, version)
        verify_pom(
            directory / f"{args.artifact}-{version}.pom",
            properties,
            args.artifact,
        )
        verify_signatures(
            directory,
            artifacts,
            args.public_key,
            args.expected_fingerprint,
        )


def main() -> int:
    args = parse_args()
    try:
        verify(args)
    except (OSError, VerificationError, zipfile.BadZipFile) as error:
        print(f"Central bundle verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Central bundle verified: {args.bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
