#!/usr/bin/env python3
"""Apply a source-verified Gloria Union .gupatch file."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import zipfile
from pathlib import Path


FORMAT = "gloria-union-apk-delta-v1"
LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_SIGNATURE = 0x04034B50


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_exact(source, target, length: int) -> None:
    remaining = length
    while remaining:
        chunk = source.read(min(4 * 1024 * 1024, remaining))
        if not chunk:
            raise RuntimeError("unexpected end of patch or source APK")
        target.write(chunk)
        remaining -= len(chunk)


def find_patch(script_dir: Path) -> Path:
    patches = sorted(script_dir.glob("*.gupatch"))
    if len(patches) != 1:
        raise RuntimeError("place exactly one .gupatch file beside apply_patch.py")
    return patches[0]


def interactive_paths(script_dir: Path) -> tuple[Path, Path, Path]:
    patch = find_patch(script_dir)
    entered = input("Drag the original Gloria Union APK here, then press Enter:\n> ").strip()
    source = Path(entered.strip('"')).expanduser().resolve()
    output = source.with_name("GloriaUnion-English-v0.25.apk")
    return source, output, patch


def apply(source: Path, output: Path, patch: Path, force: bool = False) -> None:
    if not source.is_file():
        raise RuntimeError(f"original APK not found: {source}")
    if output.exists() and not force:
        raise RuntimeError(f"output already exists: {output} (use --force to replace it)")

    with zipfile.ZipFile(patch) as patch_zip:
        manifest = json.loads(patch_zip.read("manifest.json"))
        if manifest.get("format") != FORMAT:
            raise RuntimeError("unsupported or invalid patch format")

        expected_source = manifest["source"]
        if source.stat().st_size != int(expected_source["size"]):
            raise RuntimeError(
                f"wrong original APK size: expected {expected_source['size']}, got {source.stat().st_size}"
            )
        print("Verifying original APK...")
        actual_source_hash = sha256_file(source)
        if actual_source_hash.lower() != expected_source["sha256"].lower():
            raise RuntimeError(
                "wrong original APK or a damaged file\n"
                f"expected SHA-256: {expected_source['sha256']}\n"
                f"actual SHA-256:   {actual_source_hash}"
            )

        partial = output.with_name(output.name + ".partial")
        if partial.exists():
            partial.unlink()
        entry_cache: dict[str, bytes] = {}
        try:
            with source.open("rb") as source_raw, zipfile.ZipFile(source) as source_zip, \
                    patch_zip.open("payload.bin") as payload, partial.open("wb") as target:
                operations = manifest["operations"]
                next_progress = 10
                for index, operation in enumerate(operations, 1):
                    kind = operation[0]
                    if kind == "l":
                        _, payload_offset, length = operation
                        if payload.tell() != payload_offset:
                            payload.seek(payload_offset)
                        copy_exact(payload, target, length)
                    elif kind == "r":
                        _, source_offset, length = operation
                        source_raw.seek(source_offset)
                        copy_exact(source_raw, target, length)
                    elif kind == "e":
                        _, name, source_offset, length = operation
                        if name not in entry_cache:
                            entry_cache[name] = source_zip.read(name)
                        target.write(entry_cache[name][source_offset:source_offset + length])
                    else:
                        raise RuntimeError(f"unknown patch operation: {kind}")

                    progress = index * 100 // len(operations)
                    if progress >= next_progress:
                        print(f"Patching... {progress}%")
                        next_progress += 10

            expected_target = manifest["target"]
            if partial.stat().st_size != int(expected_target["size"]):
                raise RuntimeError("patched APK has an unexpected size")
            print("Verifying translated APK...")
            actual_target_hash = sha256_file(partial)
            if actual_target_hash.lower() != expected_target["sha256"].lower():
                raise RuntimeError(
                    "patched APK verification failed\n"
                    f"expected SHA-256: {expected_target['sha256']}\n"
                    f"actual SHA-256:   {actual_target_hash}"
                )
            os.replace(partial, output)
        finally:
            if partial.exists():
                partial.unlink()

    print("\nPatch completed successfully.")
    print(f"Output: {output}")
    print(f"SHA-256: {manifest['target']['sha256']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_apk", nargs="?", type=Path)
    parser.add_argument("output_apk", nargs="?", type=Path)
    parser.add_argument("--patch", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    script_dir = Path(__file__).resolve().parent

    try:
        if args.source_apk is None:
            source, output, patch = interactive_paths(script_dir)
        else:
            source = args.source_apk.expanduser().resolve()
            output = (args.output_apk or source.with_name("GloriaUnion-English-v0.25.apk")).resolve()
            patch = (args.patch or find_patch(script_dir)).resolve()
        apply(source, output, patch, args.force)
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        print(f"\nERROR: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

