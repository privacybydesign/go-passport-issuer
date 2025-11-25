package images

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color/palette"
	"image/draw"
	"image/jpeg"
	"image/png"
	"math"
	"os"
	"sort"

	gtlv "github.com/gmrtd/gmrtd/tlv"
	xdraw "golang.org/x/image/draw"
	"pault.ag/go/cbeff/jpeg2000"
)

type tlvNode = gtlv.TlvNode

// Decodes a byte array and returns the first node.
func decodeOne(b []byte) (tlvNode, error) {
	nodes, err := gtlv.Decode(b)
	if nodes == nil || len(nodes.Nodes) == 0 {
		return nil, errors.New("no TLV nodes found")
	}
	return nodes.Nodes[0], err
}

// Gets the int representation of the TLV tag.
func tlvTag(n tlvNode) int {
	return int(n.GetTag())
}

// Gets the value of a tlv node.
func tlvValue(n tlvNode) []byte {
	return n.GetValue()
}

// Gets the length of the encoded content.
func tlvEncodedLen(n tlvNode) int {
	vlen := len(tlvValue(n))
	return berTagLen(tlvTag(n)) + berLenLen(vlen) + vlen
}

// berTagLen returns the number of bytes used to encode the tag.
// Assumes Tag is the concatenation of the tag bytes (e.g., 0x7F61 -> 2 bytes).
func berTagLen(tag int) int {
	switch {
	case tag > 0xFFFFFF:
		return 4
	case tag > 0xFFFF:
		return 3
	case tag > 0xFF:
		return 2
	default:
		return 1
	}
}

// berLenLen returns the number of bytes used to encode the length field
// in definite form (short/long form per BER/DER).
func berLenLen(l int) int {
	if l < 0x80 {
		return 1 // short form
	}
	switch {
	case l <= 0xFF:
		return 2 // 0x81 + 1 byte
	case l <= 0xFFFF:
		return 3 // 0x82 + 2 bytes
	case l <= 0xFFFFFF:
		return 4 // 0x83 + 3 bytes
	default:
		return 5 // 0x84 + 4 bytes
	}
}

// Constants & types
const (
	FID = 0x0102
	SFI = 0x02
	TAG = 0x75

	BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG = 0x7F61
	BIOMETRIC_INFORMATION_TEMPLATE_TAG       = 0x7F60

	BIOMETRIC_HEADER_TEMPLATE_BASE_TAG = 0xA1

	BIOMETRIC_DATA_BLOCK_TAG             = 0x5F2E
	BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG = 0x7F2E

	BIOMETRIC_INFORMATION_COUNT_TAG = 0x02
	SMT_TAG                         = 0x7D

	VERSION_NUMBER = 0x30313000 // "0100" per ISO/ICAO facial header
)

type ImageType int

const (
	ImageJPEG ImageType = iota
	ImageJPEG2000
)

type EfParseError struct{ msg string }

func (e EfParseError) Error() string { return e.msg }

type ImageContainer struct {
	ImageData     []byte
	ImageDataType *int
}
type EfDG2 struct {
	VersionNumber        int
	LengthOfRecord       int
	NumberOfFacialImages int
	FacialRecordDataLen  int
	NrFeaturePoints      int
	Gender               int
	EyeColor             int
	HairColor            int
	FeatureMask          int
	Expression           int
	PoseAngle            int
	PoseAngleUncertainty int
	FaceImageType        int
	ImageWidth           int
	ImageHeight          int
	ImageColorSpace      int
	SourceType           int
	DeviceType           int
	Quality              int

	ImageContainer
}

func NewEfDG2FromBytes(data []byte) (*EfDG2, error) {
	dg2 := &EfDG2{}
	if err := dg2.Parse(data); err != nil {
		return nil, err
	}
	return dg2, nil
}

func (ic *ImageContainer) ImageType() (ImageType, bool) {
	if ic.ImageDataType == nil {
		return 0, false
	}
	if *ic.ImageDataType == 0 {
		return ImageJPEG, true
	}
	return ImageJPEG2000, true
}

func (e *EfDG2) Parse(content []byte) error {
	// Outer DG2 TLV (tag 0x75)
	tlv, err := decodeOne(content)
	if err != nil {
		return err
	}
	if tlvTag(tlv) != TAG {
		return EfParseError{fmt.Sprintf("Invalid DG2 tag=%s, expected tag=%s", hex(tlvTag(tlv)), hex(TAG))}
	}

	// BIGT (0x7F61)
	bigt, err := decodeOne(tlvValue(tlv))
	if err != nil {
		return err
	}
	if tlvTag(bigt) != BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG {
		return EfParseError{fmt.Sprintf("Invalid object tag=%s, expected tag=%s",
			hex(tlvTag(bigt)), hex(BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG))}
	}

	// BICT (0x02)
	bict, err := decodeOne(tlvValue(bigt))
	if err != nil {
		return err
	}
	if tlvTag(bict) != BIOMETRIC_INFORMATION_COUNT_TAG {
		return EfParseError{fmt.Sprintf("Invalid object tag=%s, expected tag=%s",
			hex(tlvTag(bict)), hex(BIOMETRIC_INFORMATION_COUNT_TAG))}
	}
	val := tlvValue(bict)
	if len(val) < 1 {
		return EfParseError{"BICT value missing"}
	}
	bitCount := int(val[0] & 0xFF)

	// BITs follow BICT inside BIGT
	offset := tlvEncodedLen(bict)
	bv := tlvValue(bigt)
	for range bitCount {
		if offset >= len(bv) {
			return EfParseError{"Unexpected end of BIGT while reading BITs"}
		}
		bit, err := decodeOne(bv[offset:])
		if err != nil {
			return err
		}
		if err := e.readBIT(bit); err != nil {
			return err
		}
		offset += tlvEncodedLen(bit)
	}
	return nil
}

func (e *EfDG2) readBIT(bit tlvNode) error {
	if tlvTag(bit) != BIOMETRIC_INFORMATION_TEMPLATE_TAG {
		return EfParseError{fmt.Sprintf("Invalid object tag=%s, expected tag=%s",
			hex(tlvTag(bit)), hex(BIOMETRIC_INFORMATION_TEMPLATE_TAG))}
	}

	first, err := decodeOne(tlvValue(bit))
	if err != nil {
		return err
	}

	if tlvTag(first) == SMT_TAG {
		// TODO: BIT protected with secure messaging (SMT). Not handled.
		return nil
	}

	// A1... BHT (constructed)
	if (tlvTag(first) & 0xA0) == 0xA0 {
		rest, err := e.readBHT(tlvValue(bit))
		if err != nil {
			return err
		}
		return e.readBiometricDataBlock(rest)
	}

	return EfParseError{fmt.Sprintf("Unexpected BIT child tag=%s", hex(tlvTag(first)))}
}

func (e *EfDG2) readBHT(stream []byte) ([]tlvNode, error) {
	bht, err := decodeOne(stream)
	if err != nil {
		return nil, err
	}
	if tlvTag(bht) != BIOMETRIC_HEADER_TEMPLATE_BASE_TAG {
		return nil, EfParseError{fmt.Sprintf("Invalid object tag=%s, expected tag=%s",
			hex(tlvTag(bht)), hex(BIOMETRIC_HEADER_TEMPLATE_BASE_TAG))}
	}

	var (
		items   []tlvNode
		readPos = tlvEncodedLen(bht)
	)
	for readPos < len(stream) {
		t, err := decodeOne(stream[readPos:])
		if err != nil {
			return nil, err
		}
		items = append(items, t)
		readPos += tlvEncodedLen(t)
	}
	return items, nil
}

func (e *EfDG2) readBiometricDataBlock(tlvs []tlvNode) error {
	if len(tlvs) == 0 {
		return EfParseError{"Missing Biometric Data Block"}
	}
	first := tlvs[0]
	tag := tlvTag(first)
	if tag != BIOMETRIC_DATA_BLOCK_TAG && tag != BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG {
		return EfParseError{fmt.Sprintf("Invalid object tag=%s, expected tag=%s or %s",
			hex(tag), hex(BIOMETRIC_DATA_BLOCK_TAG), hex(BIOMETRIC_DATA_BLOCK_CONSTRUCTED_TAG))}
	}

	data := tlvValue(first)
	if len(data) < 4 {
		return EfParseError{"Biometric data block too short"}
	}
	// Expect 'F','A','C',0x00
	if data[0] != 0x46 || data[1] != 0x41 || data[2] != 0x43 || data[3] != 0x00 {
		return EfParseError{"Biometric data block is invalid"}
	}

	offset := 4

	var err error
	if e.VersionNumber, err = beInt(data, offset, 4); err != nil {
		return err
	}
	if e.VersionNumber != VERSION_NUMBER {
		return EfParseError{"Version of Biometric data is not valid"}
	}
	offset += 4

	if e.LengthOfRecord, err = beInt(data, offset, 4); err != nil {
		return err
	}
	offset += 4

	if e.NumberOfFacialImages, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if e.FacialRecordDataLen, err = beInt(data, offset, 4); err != nil {
		return err
	}
	offset += 4

	if e.NrFeaturePoints, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if e.Gender, err = beInt(data, offset, 1); err != nil {
		return err
	}
	offset += 1

	if e.EyeColor, err = beInt(data, offset, 1); err != nil {
		return err
	}
	offset += 1

	if e.HairColor, err = beInt(data, offset, 1); err != nil {
		return err
	}
	offset += 1

	if e.FeatureMask, err = beInt(data, offset, 3); err != nil {
		return err
	}
	offset += 3

	if e.Expression, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if e.PoseAngle, err = beInt(data, offset, 3); err != nil {
		return err
	}
	offset += 3

	if e.PoseAngleUncertainty, err = beInt(data, offset, 3); err != nil {
		return err
	}
	offset += 3

	// Skip feature points (8 bytes each)
	offset += e.NrFeaturePoints * 8
	if offset > len(data) {
		return EfParseError{"Truncated after feature points"}
	}

	if e.FaceImageType, err = beInt(data, offset, 1); err != nil {
		return err
	}
	offset += 1

	idt, err := beInt(data, offset, 1)
	if err != nil {
		return err
	}
	offset += 1
	e.ImageContainer.ImageDataType = &idt

	if e.ImageWidth, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if e.ImageHeight, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if e.ImageColorSpace, err = beInt(data, offset, 1); err != nil {
		return err
	}
	offset += 1

	if e.SourceType, err = beInt(data, offset, 1); err != nil {
		return err
	}
	offset += 1

	if e.DeviceType, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if e.Quality, err = beInt(data, offset, 2); err != nil {
		return err
	}
	offset += 2

	if offset > len(data) {
		return EfParseError{"Truncated before image data"}
	}
	e.ImageData = data[offset:]
	return nil
}

// Magic signatures to discover embedded images in DG2.
var sigs = []struct {
	sig []byte
	ext string
}{
	{[]byte{0xFF, 0xD8, 0xFF}, "jpg"}, // JPEG SOI
	{[]byte{0x00, 0x00, 0x00, 0x0C, 'j', 'P', ' ', ' ', 0x0D, 0x0A, 0x87, 0x0A}, "jp2"}, // JP2 signature box
	{[]byte{0xFF, 0x4F, 0xFF, 0x51}, "j2k"},                                             // JPEG 2000 codestream (SOC/??)
}

type chunk struct {
	start int
	ext   string
	sig   []byte
}

func (e *EfDG2) ConvertToPNG() ([]string, error) {
	return e.ImageContainer.ConvertToPNG()
}
func (ic *ImageContainer) ConvertToPNG() ([]string, error) {
	if len(ic.ImageData) == 0 {
		return nil, fmt.Errorf("data not provided")
	}

	parts := extractImagesFromDG2(ic.ImageData)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no embedded JPEG/JP2/J2K/JLS signatures found in DG2")
	}

	var count int
	var images = []string{}
	for i, p := range parts {
		img, typ, err := decodeToImage(p.data, p.ext)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip image %d (%s): %v\n", i+1, typ, err)
			continue
		}
		count++

		if base64Str, err := PNGBase64Options(img, 400, 400, 256, png.BestCompression); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode image %d (%s): %v\n", i+1, typ, err)
		} else {
			fmt.Printf("Image %d (%s) encoded successfully. \n", i+1, typ)
			images = append(images, base64Str)
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("found image-like chunks but none could be decoded—do you have JP2/J2K support installed?")
	}
	return images, nil
}

type extracted struct {
	ext  string
	data []byte
}

func extractImagesFromDG2(imageData []byte) []extracted {
	var starts []chunk
	for _, s := range sigs {
		idx := 0
		for {
			pos := bytes.Index(imageData[idx:], s.sig)
			if pos < 0 {
				break
			}
			abs := idx + pos
			starts = append(starts, chunk{start: abs, ext: s.ext, sig: s.sig})
			idx = abs + 1
		}
	}

	if len(starts) == 0 {
		return nil
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].start < starts[j].start })

	var out []extracted
	for n, st := range starts {
		end := len(imageData)
		if n < len(starts)-1 {
			end = starts[n+1].start
		}
		chunk := imageData[st.start:end]

		switch st.ext {
		case "jpg", "jls":
			// Trim to EOI if present for cleaner decoding.
			if eoi := bytes.LastIndex(chunk, []byte{0xFF, 0xD9}); eoi >= 0 {
				chunk = chunk[:eoi+2]
			}
			// For jp2/j2k we usually can save the full slice as-is.
		}
		out = append(out, extracted{ext: st.ext, data: chunk})
	}
	return out
}

func decodeToImage(b []byte, ext string) (image.Image, string, error) {
	switch ext {
	case "jpg":
		img, err := jpeg.Decode(bytes.NewReader(b))
		return img, "jpg", err
	case "jp2", "j2k":
		img, err := jpeg2000.Parse(b)
		return img, "jpeg2000", err
	default:
		// Fallback sniff: try JPEG, then JP2.
		if img, err := jpeg.Decode(bytes.NewReader(b)); err == nil {
			return img, "jpeg(sniffed)", nil
		}
		if img, err := jpeg2000.Parse(b); err == nil {
			return img, "jpeg2000(sniffed)", nil
		}
		return nil, ext, errors.New("unknown or unsupported image type")
	}
}

// PNGBase64Options encodes img to base64 PNG with optional resize + quantization.
//
// maxW/maxH: if >0, the image is downscaled to fit within this box (keeping aspect).
// colors:    if >0, convert to a paletted image (≤256 colors is typical for PNG).
//
//	With stdlib we pick a close palette; for finer control use a median-cut
//	quantizer lib later (e.g., soniakeys/quant/median).
//
// level:     png.DefaultCompression, png.BestCompression, png.BestSpeed, etc.
func PNGBase64Options(img image.Image, maxW, maxH, colors int, level png.CompressionLevel) (string, error) {
	// 1) Resize if requested
	if maxW > 0 || maxH > 0 {
		img = resizeToFit(img, maxW, maxH)
	}

	// 2) Optional quantization (palettize)
	var out = img
	if colors > 0 {
		// Choose a palette: stdlib gives us WebSafe (~216 colors) or Plan9 (256 colors).
		// For many ID/facial images Plan9 works well and keeps files tiny.
		pal := palette.Plan9
		if colors <= 216 {
			pal = palette.WebSafe
		}
		dst := image.NewPaletted(img.Bounds(), pal)
		// Floyd–Steinberg dithering in stdlib:
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

// resizeToFit scales img to fit within maxW×maxH (keeping aspect). If either is 0, the other bounds the size.
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
	// CatmullRom = high quality, good for photos/faces.
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), xdraw.Over, nil)
	return dst
}

// --- helpers -----------------------------------------------------------------

func hex(v int) string { return fmt.Sprintf("0x%X", v) }

// beInt reads a big-endian unsigned integer of size n (1..4) from b at off.
func beInt(b []byte, off, n int) (int, error) {
	if n < 1 || n > 4 {
		return 0, fmt.Errorf("beInt: unsupported size %d", n)
	}
	if off+n > len(b) {
		return 0, errors.New("beInt: out of range")
	}
	switch n {
	case 1:
		return int(b[off]), nil
	case 2:
		return int(binary.BigEndian.Uint16(b[off : off+2])), nil
	case 3:
		return int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2]), nil
	case 4:
		return int(binary.BigEndian.Uint32(b[off : off+4])), nil
	}
	return 0, nil
}
