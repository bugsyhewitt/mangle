# test fixtures

## clean.h265

A tiny (~3.3 KB) clean, conformant H.265 (HEVC) bitstream used as the fuzzing
seed. It is a single 64x64 intra (IDR) frame. It is shipped as a binary blob so
the test suite and the `mangle` examples work out of the box.

### Regenerating

Requires `ffmpeg` built with `libx265`:

```bash
ffmpeg -f lavfi -i testsrc=size=64x64:rate=1 -c:v libx265 -frames:v 1 clean.h265
```

Or, from an existing video:

```bash
ffmpeg -i input.mp4 -c:v libx265 -t 1 -s 64x64 clean.h265
```

The exact bytes may differ between x265 versions; any clean single-frame 64x64
HEVC Annex-B elementary stream that `ffmpeg -i clean.h265 -f null -` decodes with
exit code 0 is a valid replacement. The bundled blob decodes cleanly with the
ffmpeg in this repo's CI environment.
