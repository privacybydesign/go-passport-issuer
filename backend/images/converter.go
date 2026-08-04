package images

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color/palette"
	"image/draw"
	"image/jpeg"
	"image/png"
	"log/slog"
	"math"

	"github.com/gmrtd/gmrtd/document"
	xdraw "golang.org/x/image/draw"
	"pault.ag/go/cbeff/jpeg2000"
)

// ConvertDG2ImagesToPNG converts all images from a gmrtd DG2 structure to base64-encoded PNG strings
// This replaces the old signature-based approach with proper structure-based parsing using gmrtd
func ConvertDG2ImagesToPNG(dg2 *document.DG2) ([]string, error) {
	if dg2 == nil {
		return nil, fmt.Errorf("DG2 is nil")
	}

	if len(dg2.Images) == 0 {
		return nil, fmt.Errorf("no images found in DG2")
	}

	slog.Debug("Converting DG2 images to PNG", "image_count", len(dg2.Images))

	var pngImages []string

	for i, dg2Image := range dg2.Images {
		if len(dg2Image.Image) == 0 {
			return nil, fmt.Errorf("image %d has no data", i)
		}

		slog.Debug("Decoding DG2 image", "image_index", i, "data_size", len(dg2Image.Image))

		// Decode the image (supports JPEG, JPEG2000)
		img, err := decodeImage(dg2Image.Image)
		if err != nil {
			slog.Warn("Failed to decode DG2 image", "image_index", i, "error", err)
			return nil, fmt.Errorf("failed to decode image %d: %w", i, err)
		}

		bounds := img.Bounds()
		slog.Debug("Image decoded successfully", "image_index", i, "width", bounds.Dx(), "height", bounds.Dy())

		// Convert to PNG with optimization
		base64Str, err := convertImageToPNGBase64(img, 400, 400, 256, png.BestCompression)
		if err != nil {
			slog.Warn("Failed to convert image to PNG", "image_index", i, "error", err)
			return nil, fmt.Errorf("failed to convert image %d to PNG: %w", i, err)
		}

		slog.Debug("Image converted to PNG", "image_index", i, "base64_length", len(base64Str))
		pngImages = append(pngImages, base64Str)
	}

	slog.Debug("Successfully converted all DG2 images to PNG", "total_images", len(pngImages))
	return pngImages, nil
}

// decodeImage attempts to decode an image from bytes, trying multiple formats
func decodeImage(data []byte) (image.Image, error) {
	// Try JPEG first (most common)
	if img, err := jpeg.Decode(bytes.NewReader(data)); err == nil {
		return img, nil
	}

	// Try JPEG 2000 (JP2/J2K)
	if img, err := jpeg2000.Parse(data); err == nil {
		return img, nil
	}

	// Try generic image decode as fallback
	if img, _, err := image.Decode(bytes.NewReader(data)); err == nil {
		return img, nil
	}

	return nil, fmt.Errorf("unsupported or invalid image format")
}

// convertImageToPNGBase64 encodes an image to base64 PNG with optional resize and quantization
//
// maxW/maxH: if >0, the image is downscaled to fit within this box (keeping aspect ratio)
// colors:    if >0, convert to a paletted image (≤256 colors is typical for PNG)
// level:     png.DefaultCompression, png.BestCompression, png.BestSpeed, etc.
func convertImageToPNGBase64(img image.Image, maxW, maxH, colors int, level png.CompressionLevel) (string, error) {
	// 1) Resize if requested
	if maxW > 0 || maxH > 0 {
		img = resizeToFit(img, maxW, maxH)
	}

	// 2) Optional quantization (palettize)
	var out = img
	if colors > 0 {
		// Choose a palette: Plan9 (256 colors) or WebSafe (~216 colors)
		pal := palette.Plan9
		if colors <= 216 {
			pal = palette.WebSafe
		}
		dst := image.NewPaletted(img.Bounds(), pal)
		// Floyd–Steinberg dithering
		draw.FloydSteinberg.Draw(dst, dst.Bounds(), img, image.Point{})
		out = dst
	}

	// 3) Encode with chosen compression
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: level}
	if err := enc.Encode(&buf, out); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// resizeToFit scales img to fit within maxW×maxH (keeping aspect ratio)
func resizeToFit(src image.Image, maxW, maxH int) image.Image {
	bw := src.Bounds().Dx()
	bh := src.Bounds().Dy()

	if maxW <= 0 && maxH <= 0 {
		return src
	}
	if maxW <= 0 {
		scale := float64(maxH) / float64(bh)
		maxW = int(math.Round(float64(bw) * scale))
	}
	if maxH <= 0 {
		scale := float64(maxW) / float64(bw)
		maxH = int(math.Round(float64(bh) * scale))
	}

	scale := math.Min(float64(maxW)/float64(bw), float64(maxH)/float64(bh))
	if scale >= 1.0 {
		return src // already small enough
	}
	w := int(math.Max(1, math.Round(float64(bw)*scale)))
	h := int(math.Max(1, math.Round(float64(bh)*scale)))

	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	// CatmullRom = high quality, good for photos/faces
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), xdraw.Over, nil)
	return dst
}
