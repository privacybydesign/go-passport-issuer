# libpassportreader (Iris face verification engine)

Vendor-supplied static library and C header for the Iris engine that
`iris-verifier` binds through cgo (`../../engine_cgo.go`).

| File | What |
|---|---|
| `include/libpassportreader/libpassportreader.h` | C API: MRZ scanner, chip reader, face verifier, QR scanner. Only the `passportreader_face_verifier_*` calls are used. |
| `linux/x86_64/libpassportreader.a` | Static archive, Linux x86_64 only, 49 MB. Not in this repository: fetched by `fetch.sh` from a release asset, and ignored by git. |

SHA-256 of `libpassportreader.a`:

    ed7382efb56cc27e31d944336e70119714819f4737563104eb6cad452624e599

## Toolchain pin

The archive's objects are LLVM bitcode (producer: Debian clang 14.0.6) plus a
few native assembly objects. GNU ld fails on it ("file format not
recognized"). It links with clang and lld only:

    CC=clang CGO_ENABLED=1 CGO_LDFLAGS_ALLOW='-fuse-ld=lld|-flto'
    #cgo LDFLAGS: -fuse-ld=lld -flto <archive> -lstdc++ -lm -lpthread -ldl

Verified in `golang:1.26-bookworm` (clang 14, lld 14, glibc 2.36). It needs
glibc 2.34 or newer at runtime and is otherwise self-contained (TFLite,
OpenCV, OpenJPEG, libjpeg, libpng, zlib, OpenSSL, ZXing are bundled).

## Licence

Proprietary, and owned by the manufacturer ([passportreader.app](https://passportreader.app)),
not by Yivi. It is **not** covered by this repository's Apache 2.0 licence.

Yivi publishes the archive as a release asset of this repository with the
manufacturer's explicit permission. That permission covers publication only.
Downloading it grants no right to use it: running `iris-verifier`, or any image
built from it, requires your own licence with the manufacturer. See
[../../LICENSE](../../LICENSE).

## Fetching it

    ./fetch.sh

Downloads the archive into `linux/x86_64/` and checks it against the SHA-256
above, refusing anything that does not match. It is a no-op when the file is
already there and correct. The Dockerfile runs this same script, so a build
needs no separate step. `LIBPASSPORTREADER_URL` and friends override where it
comes from; see the script's header.

The archive is deliberately not committed. It is 49 MB per version, it would
sit in history forever, and the build pins it by checksum instead, which is the
stronger guarantee.

## Publishing a new version

The archive cannot be uploaded by CI, because CI has no copy of it that does not
come from a release in the first place. A person does it once per vendor drop:

1. Get the new archive from the manufacturer and confirm it is the one you
   expect.
2. Compute its SHA-256: `shasum -a 256 libpassportreader.a`.
3. Create a release on this repository tagged `libpassportreader-<yyyymmdd>`,
   marked as a pre-release so it does not look like an issuer release, and
   attach the archive as `libpassportreader-linux-x86_64.a`.
4. Update `LIBPASSPORTREADER_RELEASE` and `LIBPASSPORTREADER_SHA256` in
   `fetch.sh`, and the checksum at the top of this file.
5. Re-run the verifier's smoke test on x86_64 before the new engine reaches an
   environment: the vendor has changed names and behaviour between drops.
