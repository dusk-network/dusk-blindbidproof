package zkproof

import (
	"encoding/binary"
	"io"
)

// BinWriter holds data for a binary writer.
type BinWriter struct {
	w   io.Writer
	err error
}

// NewBinWriter returns a BinWriter for the writer provided.
func NewBinWriter(w io.Writer) BinWriter {
	return BinWriter{w: w}
}

// Write writes the binary representation of `data` into `w` using little endian
// order.
// The argument must be a fixed-size value or a slice of fixed-size
// values, or a pointer to such data.
func (w *BinWriter) Write(data interface{}) {
	if w.err != nil {
		return
	}
	w.err = binary.Write(w.w, binary.LittleEndian, data)
}

// VarWrite writes the binary representation of a variable length `data`
// into `w`.
// The argument must be a `uint*`, a `string`, or an array of `byte`;
// it will fallback to `Write` otherwise.
func (w *BinWriter) VarWrite(data interface{}) {
	if w.err != nil {
		return
	}

	switch v := data.(type) {
	case uint, uint8, uint16, uint32, uint64:
		w.Write(v)
	case string:
		w.WriteVarString(v)
	case []byte:
		w.WriteVarBytes(v)
	default:
		w.Write(v)
	}
}

// WriteVarString writes a variable length `string` into `w`.
func (w *BinWriter) WriteVarString(s string) {
	w.WriteVarBytes([]byte(s))
}

// WriteVarBytes writes a variable length byte array.
func (w *BinWriter) WriteVarBytes(b []byte) {
	w.Write(uint32(len(b)))
	w.Write(b)
}
