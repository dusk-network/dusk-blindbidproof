package zkproof

import (
	"encoding/binary"
	"fmt"
	"io"
)

// BinReader holds data for a binary reader.
type BinReader struct {
	r   io.Reader
	err error
}

// NewBinReader returns a BinReader for the reader provided.
func NewBinReader(r io.Reader) BinReader {
	return BinReader{r: r}
}

// Read reads structured binary data from `r` into `data`, using little endian
// order.
// The argument must be a fixed-size value or a slice of fixed-size
// values, or a pointer to such data.
func (r *BinReader) Read(data interface{}) {
	if r.err != nil {
		return
	}
	r.err = binary.Read(r.r, binary.LittleEndian, data)
}

// VarRead reads a variable length structured binary data from `r` into `data`,
// using little endian order.
// The argument must be a `uint*`, a `string`, or an array of `byte`.
func (r *BinReader) VarRead(data interface{}) {
	if r.err != nil {
		return
	}

	switch v := data.(type) {
	case *uint, *uint8, *uint16, *uint32, *uint64:
		r.Read(&v)
	case *string:
		*v = r.ReadVarString()
	case *[]byte:
		*v = r.ReadVarBytes()
	}
}

// ReadVarBytes reads a variable length byte array from `r`.
func (r *BinReader) ReadVarBytes() []byte {
	var n uint32
	r.Read(n)
	fmt.Println(n)
	b := make([]byte, n)
	r.Read(b)
	return b
}

// ReadVarString reads a variable length string array from `r`.
func (r *BinReader) ReadVarString() string {
	b := r.ReadVarBytes()
	return string(b)
}
