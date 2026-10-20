# Test fixtures

## `grey_200x200.jp2`, `grey_200x200.j2k`

A flat grey 200×200 image in both JPEG 2000 packagings: the JP2 container
(magic `0000000C 6A502020`) and the bare codestream (`FF4F FF51`). A chip's DG2
carries either, so `TestEnginePortraitJPEG2000` tries both.

They are deliberately faceless, the same as the grey PNG the smoke test builds
in code: the question they answer is whether the engine *decodes* JPEG 2000,
not whether it finds a face in one. Go's standard library cannot encode JPEG
2000, which is why these are files rather than generated in the test.

Regenerate with ImageMagick and OpenJPEG:

    convert -size 200x200 xc:'rgb(128,128,128)' PNG24:grey.png
    opj_compress -i grey.png -o grey_200x200.jp2
    opj_compress -i grey.png -o grey_200x200.j2k

No real portrait is committed here. To run the conclusive form of that test,
point `IRIS_SMOKE_PORTRAIT_JP2` at a JPEG 2000 portrait with a face.
