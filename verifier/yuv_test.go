package main

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"github.com/stretchr/testify/require"
)

// Each 4:2:0 chroma sample is the rounded mean of the 2x2 luma block's
// source chroma; luma is copied unchanged.
func TestToYCbCr420AveragesChroma(t *testing.T) {
	src := image.NewYCbCr(image.Rect(0, 0, 4, 2), image.YCbCrSubsampleRatio444)
	for y := 0; y < 2; y++ {
		for x := 0; x < 4; x++ {
			src.Y[src.YOffset(x, y)] = uint8(10*x + y)
			src.Cb[src.COffset(x, y)] = uint8(4*y + x)   // block 0: 0,1,4,5 → mean 2.5 → 3; block 1: 2,3,6,7 → 4.5 → 5
			src.Cr[src.COffset(x, y)] = uint8(100 + 2*x) // block 0: 100,102,100,102 → 101; block 1: 104,106 → 105
		}
	}
	dst := toYCbCr420(src)
	require.Equal(t, image.YCbCrSubsampleRatio420, dst.SubsampleRatio)
	require.Equal(t, src.Rect, dst.Rect)
	for y := 0; y < 2; y++ {
		for x := 0; x < 4; x++ {
			require.Equal(t, src.Y[src.YOffset(x, y)], dst.Y[dst.YOffset(x, y)])
		}
	}
	require.Len(t, dst.Cb, 2)
	require.Equal(t, []uint8{3, 5}, dst.Cb)
	require.Equal(t, []uint8{101, 105}, dst.Cr)
}

// Odd dimensions leave edge blocks with fewer contributors, never a division
// by zero or an index out of range.
func TestToYCbCr420OddSize(t *testing.T) {
	src := image.NewYCbCr(image.Rect(0, 0, 3, 3), image.YCbCrSubsampleRatio422)
	for i := range src.Cb {
		src.Cb[i] = 200
		src.Cr[i] = 50
	}
	dst := toYCbCr420(src)
	require.Equal(t, 2*2, len(dst.Cb))
	for i := range dst.Cb {
		require.Equal(t, uint8(200), dst.Cb[i])
		require.Equal(t, uint8(50), dst.Cr[i])
	}
}

func TestDecodeFrameJPEGColorIs420(t *testing.T) {
	data := testJPEG(t, 33, 17, color.RGBA{R: 200, G: 30, B: 90, A: 255})
	img, err := decodeFrameJPEG(data)
	require.NoError(t, err)
	require.Equal(t, image.YCbCrSubsampleRatio420, img.SubsampleRatio)
	require.Equal(t, image.Rect(0, 0, 33, 17), img.Rect)
	// The decoder pads to whole MCUs and hands out a sub-image, so the plane
	// buffers are larger than the picture; the strides are what the engine
	// call relies on.
	require.GreaterOrEqual(t, img.YStride, 33)
	require.GreaterOrEqual(t, img.CStride, 17)
	require.Less(t, img.COffset(32, 16), len(img.Cb))
	require.Less(t, img.YOffset(32, 16), len(img.Y))
}

// A greyscale JPEG decodes to *image.Gray; the frame still has to come out
// as three planes with neutral chroma.
func TestDecodeFrameJPEGGray(t *testing.T) {
	gray := image.NewGray(image.Rect(0, 0, 8, 8))
	for i := range gray.Pix {
		gray.Pix[i] = 77
	}
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, gray, &jpeg.Options{Quality: 100}))

	img, err := decodeFrameJPEG(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, image.YCbCrSubsampleRatio420, img.SubsampleRatio)
	require.InDelta(t, 77, img.Y[0], 2)
	require.Equal(t, uint8(128), img.Cb[0])
	require.Equal(t, uint8(128), img.Cr[0])
}

func TestDecodeFrameJPEGGarbage(t *testing.T) {
	_, err := decodeFrameJPEG([]byte("definitely not a jpeg"))
	require.Error(t, err)
}
