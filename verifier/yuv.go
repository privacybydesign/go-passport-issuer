package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
)

// decodeFrameJPEG decodes a JPEG into full-range 4:2:0 YCbCr planes, the
// layout of the library's run_YCbCr420FullRangeTriPlanar entry point.
//
// JFIF JPEGs carry full-range YCbCr, so no range conversion is needed. Only
// the chroma subsampling can differ: cameras encode 4:2:0, but 4:4:4 and
// 4:2:2 are legal and are normalised here.
func decodeFrameJPEG(data []byte) (*image.YCbCr, error) {
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode jpeg: %w", err)
	}
	if src, ok := img.(*image.YCbCr); ok {
		if src.SubsampleRatio == image.YCbCrSubsampleRatio420 {
			return src, nil
		}
		return toYCbCr420(src), nil
	}
	// Greyscale and CMYK JPEGs decode to other image types; rare from a
	// camera, so the slow per-pixel path is fine.
	return anyToYCbCr420(img), nil
}

// toYCbCr420 keeps luma and averages the source chroma of every 2x2 luma
// block into one 4:2:0 sample.
func toYCbCr420(src *image.YCbCr) *image.YCbCr {
	r := src.Rect
	dst := image.NewYCbCr(r, image.YCbCrSubsampleRatio420)
	for y := r.Min.Y; y < r.Max.Y; y++ {
		so := src.YOffset(r.Min.X, y)
		do := dst.YOffset(r.Min.X, y)
		copy(dst.Y[do:do+r.Dx()], src.Y[so:so+r.Dx()])
	}
	acc := newChromaAccumulator(len(dst.Cb))
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			si := src.COffset(x, y)
			acc.add(dst.COffset(x, y), src.Cb[si], src.Cr[si])
		}
	}
	acc.write(dst)
	return dst
}

// anyToYCbCr420 converts through the colour model; only for non-YCbCr JPEGs.
func anyToYCbCr420(img image.Image) *image.YCbCr {
	r := img.Bounds()
	dst := image.NewYCbCr(r, image.YCbCrSubsampleRatio420)
	acc := newChromaAccumulator(len(dst.Cb))
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			cr, cg, cb, _ := img.At(x, y).RGBA()
			yy, u, v := color.RGBToYCbCr(uint8(cr>>8), uint8(cg>>8), uint8(cb>>8))
			dst.Y[dst.YOffset(x, y)] = yy
			acc.add(dst.COffset(x, y), u, v)
		}
	}
	acc.write(dst)
	return dst
}

// chromaAccumulator averages chroma samples per destination index, rounding
// to nearest. Blocks at odd edges simply have fewer contributors.
type chromaAccumulator struct {
	cb, cr []uint32
	n      []uint16
}

func newChromaAccumulator(size int) *chromaAccumulator {
	return &chromaAccumulator{cb: make([]uint32, size), cr: make([]uint32, size), n: make([]uint16, size)}
}

func (a *chromaAccumulator) add(i int, cb, cr uint8) {
	a.cb[i] += uint32(cb)
	a.cr[i] += uint32(cr)
	a.n[i]++
}

func (a *chromaAccumulator) write(dst *image.YCbCr) {
	for i, n := range a.n {
		if n == 0 {
			continue
		}
		nn := uint32(n)
		dst.Cb[i] = uint8((a.cb[i] + nn/2) / nn)
		dst.Cr[i] = uint8((a.cr[i] + nn/2) / nn)
	}
}
