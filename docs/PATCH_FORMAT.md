# Patch format

The `.gupatch` file uses the project-specific
`gloria-union-apk-delta-v1` format. It is a ZIP container with two members:

- `manifest.json` contains source/target hashes and reconstruction operations.
- `payload.bin` contains only target bytes that cannot be recovered from the
  supported original APK.

Operations either copy an absolute byte range from the original APK, copy a
range from a decompressed original ZIP member, or insert a range from the patch
payload. The patcher writes to a temporary `.partial` file and only renames it to
the requested output after the final SHA-256 passes.

The source APK is accepted only when both its exact size and complete SHA-256
match the manifest. The result is likewise checked against the complete target
SHA-256, producing the exact tested and signed v0.25 APK.

The format and patcher use only Python's standard library. Build-time generation
is implemented in `tools/build_apk_delta.py`; end-user application is implemented
in `patcher/apply_patch.py`.

