#!/usr/bin/env python3
"""Build a source-verified, byte-exact Gloria Union APK delta.

The generated .gupatch contains only target bytes that cannot be recovered from
the exact original APK. Large unchanged ranges are copied directly from the
user-supplied source APK by the public patcher.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import struct
import tempfile
import time
import zipfile
from collections import defaultdict
from pathlib import Path


FORMAT = "gloria-union-apk-delta-v1"
LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_SIGNATURE = 0x04034B50
BIG_BLOCK = 1024 * 1024
SMALL_BLOCK = 4096
CDC_MIN = 2048
CDC_MASK = 8191
CDC_MAX = 32768
MASK64 = (1 << 64) - 1


def gear_table() -> tuple[int, ...]:
    value = 0x9E3779B97F4A7C15
    values = []
    for _ in range(256):
        value ^= value >> 12
        value ^= (value << 25) & MASK64
        value ^= value >> 27
        values.append((value * 0x2545F4914F6CDD1D) & MASK64)
    return tuple(values)


GEAR = gear_table()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def data_bounds(raw: mmap.mmap, info: zipfile.ZipInfo) -> tuple[int, int]:
    header = raw[info.header_offset:info.header_offset + LOCAL_HEADER.size]
    fields = LOCAL_HEADER.unpack(header)
    if fields[0] != LOCAL_SIGNATURE:
        raise ValueError(f"invalid local ZIP header for {info.filename}")
    name_length, extra_length = fields[-2:]
    start = info.header_offset + LOCAL_HEADER.size + name_length + extra_length
    return start, start + info.compress_size


def cdc_chunks(data: memoryview):
    start = 0
    rolling = 0
    for index in range(len(data)):
        rolling = ((rolling << 1) + GEAR[data[index]]) & MASK64
        length = index + 1 - start
        if length >= CDC_MIN and ((rolling & CDC_MASK) == 0 or length >= CDC_MAX):
            yield start, length
            start = index + 1
            rolling = 0
    if start < len(data):
        yield start, len(data) - start


class PatchWriter:
    def __init__(self, payload_path: Path):
        self.payload_path = payload_path
        self.payload = payload_path.open("wb")
        self.payload_size = 0
        self.operations: list[list] = []
        self.stats = defaultdict(int)

    def close(self) -> None:
        self.payload.close()

    def _append(self, operation: list) -> None:
        if self.operations:
            prior = self.operations[-1]
            if operation[0] == prior[0] == "l" and prior[1] + prior[2] == operation[1]:
                prior[2] += operation[2]
                return
            if operation[0] == prior[0] == "r" and prior[1] + prior[2] == operation[1]:
                prior[2] += operation[2]
                return
            if (operation[0] == prior[0] == "e" and operation[1] == prior[1]
                    and prior[2] + prior[3] == operation[2]):
                prior[3] += operation[3]
                return
        self.operations.append(operation)

    def literal(self, data) -> None:
        if not data:
            return
        offset = self.payload_size
        blob = bytes(data)
        self.payload.write(blob)
        self.payload_size += len(blob)
        self.stats["literal_bytes"] += len(blob)
        self._append(["l", offset, len(blob)])

    def raw(self, offset: int, length: int) -> None:
        if not length:
            return
        self.stats["source_bytes"] += length
        self._append(["r", offset, length])

    def entry(self, name: str, offset: int, length: int) -> None:
        if not length:
            return
        self.stats["source_bytes"] += length
        self._append(["e", name, offset, length])


def equal(a: memoryview, b: memoryview) -> bool:
    return len(a) == len(b) and a == b


def fixed_delta(writer: PatchWriter, source: memoryview, target: memoryview,
                copy_callback) -> None:
    if len(source) != len(target):
        raise ValueError("fixed delta requires equal sizes")
    for big_start in range(0, len(target), BIG_BLOCK):
        big_end = min(len(target), big_start + BIG_BLOCK)
        if equal(source[big_start:big_end], target[big_start:big_end]):
            copy_callback(big_start, big_end - big_start)
            continue
        for start in range(big_start, big_end, SMALL_BLOCK):
            end = min(big_end, start + SMALL_BLOCK)
            if equal(source[start:end], target[start:end]):
                copy_callback(start, end - start)
            else:
                writer.literal(target[start:end])


def content_delta(writer: PatchWriter, source: memoryview, target: memoryview,
                  copy_callback) -> None:
    index: dict[tuple[bytes, int], list[int]] = defaultdict(list)
    for offset, length in cdc_chunks(source):
        digest = hashlib.blake2b(source[offset:offset + length], digest_size=16).digest()
        index[(digest, length)].append(offset)

    for target_offset, length in cdc_chunks(target):
        chunk = target[target_offset:target_offset + length]
        digest = hashlib.blake2b(chunk, digest_size=16).digest()
        match = None
        for source_offset in index.get((digest, length), ()):
            if equal(source[source_offset:source_offset + length], chunk):
                match = source_offset
                break
        if match is None:
            writer.literal(chunk)
        else:
            copy_callback(match, length)


def build(source_path: Path, target_path: Path, output_path: Path) -> dict:
    source_hash = sha256_file(source_path)
    target_hash = sha256_file(target_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="gloria-patch-") as temporary:
        payload_path = Path(temporary) / "payload.bin"
        writer = PatchWriter(payload_path)
        try:
            with source_path.open("rb") as source_file, target_path.open("rb") as target_file:
                source_map = mmap.mmap(source_file.fileno(), 0, access=mmap.ACCESS_READ)
                target_map = mmap.mmap(target_file.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    with zipfile.ZipFile(source_path) as source_zip, zipfile.ZipFile(target_path) as target_zip:
                        source_infos = {item.filename: item for item in source_zip.infolist()}
                        source_bounds = {
                            name: data_bounds(source_map, info) for name, info in source_infos.items()
                        }
                        source_cache: dict[str, bytes] = {}
                        target_infos = sorted(target_zip.infolist(), key=lambda item: item.header_offset)
                        cursor = 0

                        for item in target_infos:
                            target_start, target_end = data_bounds(target_map, item)
                            writer.literal(target_map[cursor:target_start])
                            source_info = source_infos.get(item.filename)
                            source_raw = None
                            target_raw = None
                            source_plain = None
                            handled = False

                            if source_info is not None:
                                source_start, source_end = source_bounds[item.filename]
                                source_raw = memoryview(source_map)[source_start:source_end]
                                target_raw = memoryview(target_map)[target_start:target_end]

                                if equal(source_raw, target_raw):
                                    writer.raw(source_start, len(target_raw))
                                    handled = True
                                elif item.compress_type == zipfile.ZIP_STORED:
                                    if source_info.compress_type == zipfile.ZIP_STORED:
                                        source_plain = source_raw
                                        callback = lambda offset, length, base=source_start: writer.raw(
                                            base + offset, length
                                        )
                                    else:
                                        source_cache[item.filename] = source_zip.read(item.filename)
                                        source_plain = memoryview(source_cache[item.filename])
                                        callback = lambda offset, length, name=item.filename: writer.entry(
                                            name, offset, length
                                        )

                                    if len(source_plain) == len(target_raw):
                                        fixed_delta(writer, source_plain, target_raw, callback)
                                    else:
                                        content_delta(writer, source_plain, target_raw, callback)
                                    handled = True

                            if not handled:
                                writer.literal(target_map[target_start:target_end])
                            cursor = target_end
                            source_plain = None
                            source_raw = None
                            target_raw = None

                        writer.literal(target_map[cursor:])
                finally:
                    source_map.close()
                    target_map.close()
        finally:
            writer.close()

        manifest = {
            "format": FORMAT,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": {
                "filename": source_path.name,
                "size": source_path.stat().st_size,
                "sha256": source_hash,
            },
            "target": {
                "filename": "GloriaUnion-English-v0.25.apk",
                "size": target_path.stat().st_size,
                "sha256": target_hash,
            },
            "payload_size": writer.payload_size,
            "operation_count": len(writer.operations),
            "operations": writer.operations,
            "statistics": dict(writer.stats),
        }
        with zipfile.ZipFile(output_path, "w", allowZip64=True) as archive:
            archive.writestr(
                "manifest.json",
                json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
            archive.write(payload_path, "payload.bin", compress_type=zipfile.ZIP_STORED)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_apk", type=Path)
    parser.add_argument("target_apk", type=Path)
    parser.add_argument("output_patch", type=Path)
    args = parser.parse_args()
    manifest = build(args.source_apk.resolve(), args.target_apk.resolve(), args.output_patch.resolve())
    summary = {key: manifest[key] for key in (
        "format", "source", "target", "payload_size", "operation_count", "statistics"
    )}
    summary["patch_size"] = args.output_patch.resolve().stat().st_size
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
