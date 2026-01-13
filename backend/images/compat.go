package images

import (
	"fmt"
	"image/png"
	"log/slog"
)

// ImageType represents the type of biometric image data
type ImageType int

const (
	ImageJPEG ImageType = iota
	ImageJPEG2000
)

// ImageContainer holds raw image data and its type
// This is kept for backward compatibility with driving license code (DG5, DG6)
type ImageContainer struct {
	ImageData     []byte
	ImageDataType *int
}

// ImageType returns the type of image data in the container
func (ic *ImageContainer) ImageType() (ImageType, bool) {
	if ic.ImageDataType == nil {
		return 0, false
	}
	if *ic.ImageDataType == 0 {
		return ImageJPEG, true
	}
	return ImageJPEG2000, true
}

// ConvertToPNG converts the image data to PNG format and returns it as base64-encoded strings
func (ic *ImageContainer) ConvertToPNG() ([]string, error) {
	if len(ic.ImageData) == 0 {
		return nil, fmt.Errorf("no image data provided")
	}

	slog.Debug("Converting ImageContainer to PNG", "data_size", len(ic.ImageData))

	// Decode the image
	img, err := decodeImage(ic.ImageData)
	if err != nil {
		slog.Warn("Failed to decode ImageContainer image", "error", err)
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	bounds := img.Bounds()
	slog.Debug("ImageContainer image decoded", "width", bounds.Dx(), "height", bounds.Dy())

	// Convert to PNG with optimization
	base64Str, err := convertImageToPNGBase64(img, 400, 400, 256, png.BestCompression)
	if err != nil {
		slog.Warn("Failed to convert ImageContainer to PNG", "error", err)
		return nil, fmt.Errorf("failed to convert to PNG: %w", err)
	}

	slog.Debug("ImageContainer converted to PNG successfully", "base64_length", len(base64Str))
	return []string{base64Str}, nil
}
