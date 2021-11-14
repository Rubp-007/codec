package scanlines

import (
	"bytes"
	"fmt"
	"math"
	"steganographypng/chunk"
	"steganographypng/scanlines/filters"
)

// TODO: Scanlines bytes are filtered, that is why before changing the bytes
// within the scanline we need to unfilter it first.
// https://www.w3.org/TR/PNG-Filters.html

// How to calculate bpp?
//
// Bit Depth  = number of bits in a sample
// Color type = number of samples
//
// BPP = Color type * bitdepth

// PRESERVE: At each scaline we can compromise only 70% of its bytes
const PRESERVE float32 = 0.9 //0.0075

// Scanliens Represensts the **parsed** union of all IDAT chunks.
//
// When talking about PNG files _the real_ image data lives inside the IDAT
// chunk, however this data is compressed and scattered in multiple IDAT chunks.
// This class is the actual representation of those IDAT chunks.
type Scanliens struct {
	length                    int
	bytesPerScanline          uint32
	bytesAvailablePerScanline uint32
	scalines                  [][]byte
	header                    map[string]interface{}
}

// HideBytes Tries to hide some bytes inside the specified scanline
func (t *Scanliens) HideBytes(data []byte, bitloss int) error {
	return t.peekScanlines(data, bitloss, true)
}

// RevealBytes Tries to hide some bytes inside the specified scanline
func (t *Scanliens) RevealBytes(data []byte, bitloss int) error {
	return t.peekScanlines(data, bitloss, false)
}

// ToChunks Converts the scanlines into an array of IDAT chunks
func (t *Scanliens) ToChunks(chunkSize uint32) ([]chunk.Chunk, error) {
	// A basic Array.flat
	data := []byte{}

	for _, el := range t.scalines {
		data = append(data, el...)
	}

	data, err := compress(data)
	if err != nil {
		return nil, err
	}

	var chunks []chunk.Chunk = chunk.BuildIDATChunks(bytes.NewBuffer(data), chunkSize)

	return chunks, nil
}

// FromChunks Creates a new Scanlines instance from an array of chunks
func FromChunks(chunks []chunk.Chunk, header map[string]interface{}) (Scanliens, uint32, error) {
	data, maxSize := assembleIDATChunks(chunks)

	data, err := decompress(data)
	if err != nil {
		return Scanliens{}, 0, err
	}

	bytesPerScanline := uint32(len(data)) / header["Height"].(uint32)

	var scanlines [][]byte
	for i, size := uint32(0), uint32(len(data)); i < size; {
		end := i + bytesPerScanline

		if end > size {
			end = size
		}

		scanlines = append(scanlines, data[i:end])

		i = end
	}

	return Scanliens{
		length:                    len(scanlines),
		bytesPerScanline:          bytesPerScanline,
		bytesAvailablePerScanline: uint32(float32(bytesPerScanline-1) * PRESERVE),
		scalines:                  scanlines,
		header:                    header,
	}, maxSize, nil
}

func (t *Scanliens) ToggleFilter(undo bool, lines []int) {
	if lines == nil {
		lines = make([]int, len(t.scalines))
		for i := 0; i < len(lines); i++ {
			lines[i] = i
		}
	}

	var previousScanline []byte = make([]byte, t.bytesPerScanline)
	var originalScanlines [][]byte = make([][]byte, len(t.scalines))

	copy(originalScanlines, t.scalines)

	for j := 0; j < len(lines); j++ {
		i := lines[j]

		filterType := t.scalines[i][0]

		// Filter type 0: do nothing
		filterFn := func(current, previous []byte, undo bool, header map[string]interface{}) []byte {
			return append([]byte{filterType}, current...)
		}

		switch filterType {
		case 1:
			filterFn = filters.Sub
			break
		case 2:
			filterFn = filters.Up
			break
		case 3:
			filterFn = filters.Average
			break
		case 4:
			filterFn = filters.Paeth
			break
		}

		t.scalines[i] = filterFn(t.scalines[i][1:], previousScanline[1:], undo, t.header)

		if undo {
			previousScanline = t.scalines[i]
		} else {
			previousScanline = originalScanlines[i]
		}
	}

	originalScanlines = nil
	previousScanline = nil
}

// Get Returns the specified scaline
func (t *Scanliens) Get(index int) []byte {
	return t.scalines[index]
}

// GetScanlines Returns all scanlines
func (t *Scanliens) GetScanlines() [][]byte {
	return t.scalines
}

// ToString Returns a string representation of this scalines
func (t *Scanliens) ToString() string {
	lines := " [\n"
	for i := 0; i < len(t.scalines); i += 1 {
		lines += "\t\t" + fmt.Sprintf("%v) %v", i, int(t.scalines[i][0])) + " [...]\n"
	}
	lines += "\t]"

	text := `
	Scanlines {
		length: ` + fmt.Sprintf("%v", t.length) + `
		bytesPerScanline: ` + fmt.Sprintf("%v", t.bytesPerScanline) + `
		bytesAvailablePerScanline: ` + fmt.Sprintf("%v", t.bytesAvailablePerScanline) + `
		scanlines: ` + lines + `
	}`

	return text
}

// CanComport Determines wheather this scanlines can comport an x amount of data
//
// **@param** _dataSize dataSize_ Size of the data to be hide
func (t *Scanliens) canComport(dataSize uint32) bool {

	// At minumum each scanline should have at leas 8 bytes available
	if t.bytesAvailablePerScanline < 8 {
		return false
	}

	if dataSize > t.bytesAvailablePerScanline*uint32(t.length) {
		return false
	}

	return true
}

// bestScanlinesFor Returns an array with the best scanlines to hide data.
// The data will be devided between the maximum amount of scanlines.
func (t *Scanliens) bestScanlinesFor(data []byte, bitloss int) ([]int, error) {
	// How many bytes we need to encode ``data`
	actualDataSize := uint32(len(data) * len(SectionsMap[bitloss-1]))

	if !t.canComport(actualDataSize) {
		return nil, ErrDataTooSmall
	}

	// How many bytes we gonna use in each scanline
	// usedBytesPerScanline := int(math.Ceil(float64(actualDataSize) / float64(t.length)))

	return nil, nil
}

// scanlinesFor Returns an array with the best scanliens to hide data
func (t *Scanliens) scanlinesFor(data []byte, bitloss int) ([]int, error) {
	actualDataSize := uint32(len(data) * len(SectionsMap[bitloss-1]))

	// Less than a 8 bits per scanline is ultrageous!
	if !t.canComport(actualDataSize) {
		return nil, ErrDataTooSmall
	}

	scanlinesNeeded := int(math.Ceil(float64(actualDataSize) / float64(t.bytesAvailablePerScanline)))

	if scanlinesNeeded == 1 {
		scanlinesNeeded = 2
	}

	step := int((t.length - 1) / (scanlinesNeeded - 1))

	scanlines := []int{}
	for i, j := 0, 0; i < scanlinesNeeded; i++ {
		scanlines = append(scanlines, j)

		j += step
	}

	return scanlines, nil
}

// peekScanlines Select the best bytes on each scanline to hide info
func (t *Scanliens) peekScanlines(data []byte, bitloss int, replace bool) error {
	t.ToggleFilter(true, nil)

	scanliens, err := t.scanlinesFor(data, bitloss)
	if err != nil {
		return err
	}

	// How many bytes we gonna encode in one byte
	var bytesPerByte = uint32(len(SectionsMap[bitloss-1]))

	// how many bytes we can **really** fit into a scanline.
	var maxFitted = int(math.Floor(float64(t.bytesAvailablePerScanline / bytesPerByte)))

	for i, j := 0, 0; i < len(scanliens); i++ {

		end := j + maxFitted

		if end > len(data) {
			end = len(data)
		}

		err = t.peekScanlineBytes(Slice{data: data, begin: j, end: end}, scanliens[i], bitloss, replace)
		if err != nil {
			return err
		}

		j = end
	}

	t.ToggleFilter(false, nil)

	return nil
}

// peekScanlineBytes Will uniformly select some bytes from the selected scanline.
// If replace is true it will also edit those bytes.
//
// **@param** _data *[]byte_ Data to be distributed
//
// **@param** _index int_ Scanline index
//
// **@param** _bitloss int_ How many bits of a byte we should use to enconde information
//
// **@param** _replace bool_ Replace the selected bytes or just retrieve it
func (t *Scanliens) peekScanlineBytes(data Slice, index int, bitloss int, replace bool) error {
	scanline := t.scalines[index]

	bytesPerByte := len(SectionsMap[bitloss-1])

	actualSize := uint32(data.size() * bytesPerByte)
	step := (t.bytesAvailablePerScanline - 1) / (actualSize - 1)

	k := uint32(1) // first byte of scanline is the filter type

	for i := 0; i < data.size(); i++ {
		parts := Div(data.get(i), bitloss)

		for j := 0; j < len(parts); j++ {
			bits := parts[j]

			var mask byte = (((1 << (8 - bits[1])) - 1) << bits[1])

			if replace {
				scanline[k] = ((scanline)[k] & mask) | bits[0]
			} else {
				parts[j][0] = (scanline)[k] & ((1 << bits[1]) - 1)
			}

			k = k + step
		}

		if !replace {
			data.set(i, Unite(parts))
		}
	}

	return nil
}

// Takes an Array of chunk.Chunk and appends all into a big IDAT chunk
func assembleIDATChunks(chunks []chunk.Chunk) ([]byte, uint32) {
	data := []byte{}

	var maxSize uint32 = 0

	for _, element := range chunks {
		if element.GetType() == "IDAT" {
			data = append(data, element.Data...)
			maxSize = uint32(math.Max(float64(maxSize), float64(element.GetDataSize())))
		}
	}

	return data, maxSize
}
