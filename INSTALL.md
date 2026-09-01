# Installation

## Requirements

- Windows
- Python 3
- A legally obtained copy of the exact supported original Android APK
- `GloriaUnion-English-v0.25-Patch-Windows.zip` from this repository's Releases
  page

## Applying the patch

1. Extract every file from the patch ZIP into one folder.
2. Double-click `PATCH_WINDOWS.bat`.
3. Drag the original APK into the command window and press Enter.
4. Wait for the original and translated SHA-256 checks to complete.
5. Install the resulting `GloriaUnion-English-v0.25.apk`.

The patcher never modifies the original file. It refuses unsupported or damaged
APKs before creating output.

## Supported original APK

- Size: `714,729,597` bytes
- SHA-256: `e10783d344c7a2fb8c229d224d20953946f1c91caac7eaa87fa7ce1fa9829c5e`

## Expected translated APK

- Size: `675,207,299` bytes
- SHA-256: `57f01f5de4e603ed33c69d926f853ec65d0ff06f7d165eaecc6c56d484e65d19`

Back up existing saves or the emulator instance before replacing an installed
build. Android may reject an in-place update when the currently installed version
uses a different signing certificate.
