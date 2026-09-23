//go:build linux && amd64 && cgo

package main

// The archive is LLVM bitcode produced by clang 14 plus a few native objects,
// so it links only with clang and lld: build with CC=clang and
// CGO_LDFLAGS_ALLOW='-fuse-ld=lld|-flto' (see the Dockerfile).

/*
#cgo CFLAGS: -I${SRCDIR}/third_party/libpassportreader/include
#cgo LDFLAGS: -fuse-ld=lld -flto ${SRCDIR}/third_party/libpassportreader/linux/x86_64/libpassportreader.a -lstdc++ -lm -lpthread -ldl
#include <libpassportreader/libpassportreader.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"image"
	"unsafe"
)

// engineAvailable tells readyz whether to also prove that a worker can start.
const engineAvailable = true

// cEngine binds the vendor library. There is no handle: all state is
// process-global, which is why each worker process holds exactly one.
type cEngine struct{}

func newEngine() (Engine, error) { return cEngine{}, nil }

// check maps the library's int results to errors. A negative value is a
// failure (set_portrait returns -1 on malformed base64); the smoke test pins
// this convention for the other calls.
func check(name string, rc C.int) error {
	if rc < 0 {
		return fmt.Errorf("%s returned %d", name, int(rc))
	}
	return nil
}

func (cEngine) Clear() error {
	return check("clear", C.passportreader_face_verifier_clear())
}

func (cEngine) SetPortrait(base64Portrait string) error {
	// A NUL-terminated copy in Go memory, passed for the duration of the
	// call only, avoids stdlib.h and C.free for a single string argument.
	buf := append([]byte(base64Portrait), 0)
	rc := C.passportreader_face_verifier_set_portrait((*C.char)(unsafe.Pointer(&buf[0])))
	return check("set_portrait", rc)
}

func (cEngine) Run(img *image.YCbCr, orientation uint8) error {
	if img.SubsampleRatio != image.YCbCrSubsampleRatio420 {
		return fmt.Errorf("frame is %v, want 4:2:0", img.SubsampleRatio)
	}
	w, h := img.Rect.Dx(), img.Rect.Dy()
	if w == 0 || h == 0 {
		return errors.New("frame is empty")
	}
	y := img.Y[img.YOffset(img.Rect.Min.X, img.Rect.Min.Y):]
	c := img.COffset(img.Rect.Min.X, img.Rect.Min.Y)
	cb, cr := img.Cb[c:], img.Cr[c:]
	rc := C.passportreader_face_verifier_run_YCbCr420FullRangeTriPlanar(
		(*C.uchar)(unsafe.Pointer(&y[0])),
		(*C.uchar)(unsafe.Pointer(&cb[0])),
		(*C.uchar)(unsafe.Pointer(&cr[0])),
		C.uint(img.YStride), 1,
		C.uint(img.CStride), 1,
		C.uint(img.CStride), 1,
		C.uint(w), C.uint(h),
		C.passportreader_image_orientation_t(orientation),
	)
	return check("run_YCbCr420FullRangeTriPlanar", rc)
}

func (cEngine) Verdict() Verdict {
	return Verdict{
		State:    EngineState(C.passportreader_face_verifier_state()),
		Distance: float64(C.passportreader_face_verifier_distance()),
	}
}
