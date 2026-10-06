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
	"runtime"
	"unsafe"
)

// engineAvailable tells readyz whether to also prove that a worker can start.
const engineAvailable = true

// cEngine binds one passportreader_face_verification_t. The library has no
// failed state; failed records that initiate refused the portrait.
type cEngine struct {
	h      *C.passportreader_face_verification_t
	state  C.passportreader_face_verification_state_t
	failed bool
}

func newEngine() (Engine, error) { return &cEngine{}, nil }

// check maps the library's results to errors: every call returns 0 on
// success and 1 on failure.
func check(name string, rc C.int) error {
	if rc != 0 {
		return fmt.Errorf("%s returned %d", name, int(rc))
	}
	return nil
}

func (e *cEngine) Clear() error {
	if e.h != nil {
		_ = C.passportreader_face_verification_destroy(e.h)
		e.h = nil
	}
	e.state, e.failed = C.PASSPORTREADER_FACE_VERIFICATION_INITIATED, false
	return check("create", C.passportreader_face_verification_create(&e.h))
}

func (e *cEngine) SetPortrait(portrait []byte) error {
	if e.h == nil {
		return errors.New("set portrait before clear")
	}
	if len(portrait) == 0 {
		return errors.New("portrait is empty")
	}
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(&portrait[0])
	b := C.passportreader_bytes_t{data: (*C.uchar)(unsafe.Pointer(&portrait[0])), length: C.size_t(len(portrait))}
	// initiate does not say why it refused; an undecodable portrait and one
	// without a face look the same here. Either way the session is decided.
	if C.passportreader_face_verification_initiate(e.h, b) != 0 {
		e.failed = true
	}
	return nil
}

func (e *cEngine) Run(img *image.YCbCr, orientation uint8) error {
	if e.h == nil {
		return errors.New("run before clear")
	}
	if e.failed || e.state == C.PASSPORTREADER_FACE_VERIFICATION_COMPLETED {
		return nil
	}
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

	// The image struct lives in Go memory and points at the planes, which
	// cgo allows only for pinned memory.
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(&y[0])
	pin.Pin(&cb[0])
	pin.Pin(&cr[0])
	var in C.passportreader_image_t
	in.format = C.PASSPORTREADER_IMAGE_FORMAT_YCBCR_420_TRIPLANAR
	in.planes[0] = C.passportreader_image_plane_t{data: (*C.uchar)(unsafe.Pointer(&y[0])), row_stride: C.uint(img.YStride), pixel_stride: 1}
	in.planes[1] = C.passportreader_image_plane_t{data: (*C.uchar)(unsafe.Pointer(&cb[0])), row_stride: C.uint(img.CStride), pixel_stride: 1}
	in.planes[2] = C.passportreader_image_plane_t{data: (*C.uchar)(unsafe.Pointer(&cr[0])), row_stride: C.uint(img.CStride), pixel_stride: 1}
	in.plane_count = 3
	in.width, in.height = C.uint(w), C.uint(h)
	in.orientation = C.passportreader_frame_orientation_t(orientation)
	// JFIF JPEGs carry full-range YCbCr (see decodeFrameJPEG).
	in.color_range = C.PASSPORTREADER_COLOR_RANGE_FULL

	var status C.passportreader_face_verification_status_t
	if err := check("process", C.passportreader_face_verification_process(e.h, &in, &status)); err != nil {
		return err
	}
	e.state = status.state
	return nil
}

func (e *cEngine) Verdict() Verdict {
	switch {
	case e.failed:
		return Verdict{State: StateFailed}
	case e.state != C.PASSPORTREADER_FACE_VERIFICATION_COMPLETED:
		return Verdict{State: StateInitiated}
	}
	// The result copies the retained frames and the face PNG, so it is read
	// only once the verification has completed.
	var res C.passportreader_face_verification_result_t
	if C.passportreader_face_verification_result(e.h, &res) != 0 {
		// Completed without a readable score: report it as a failure rather
		// than as a score of 0 that a threshold might misread.
		return Verdict{State: StateFailed}
	}
	defer C.passportreader_face_verification_result_free(&res)
	return Verdict{State: StateCompleted, Score: float64(res.score)}
}
