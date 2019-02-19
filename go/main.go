package main

// #cgo LDFLAGS: libblindbid.dylib
// #cgo pkg-config: ./libblindbid.pc
// #include "./libblindbid.h"
import "C"
import (
	"crypto/rand"
	"os"
)

func main() {
	d := genRandomBytes(32)
	k := genRandomBytes(32)
	y := genRandomBytes(32)
	yInv := genRandomBytes(32)
	q := genRandomBytes(32)
	zImg := genRandomBytes(32)
	seed := genRandomBytes(32)

	dPtr := sliceToPtr(d)
	kPtr := sliceToPtr(k)
	yPtr := sliceToPtr(y)
	yInvPtr := sliceToPtr(yInv)
	qPtr := sliceToPtr(q)
	zImgPtr := sliceToPtr(zImg)
	seedPtr := sliceToPtr(seed)

	pubList := make([]byte, 0, 32*8)

	for i := 0; i < 8; i++ {
		pubList = append(pubList, genRandomBytes(32)...)
	}

	pubListPtr := sliceToPtr(pubList)
	cPubListLen := C.size_t(len(pubList))
	C.prover(dPtr, kPtr, yPtr, yInvPtr, qPtr, zImgPtr, seedPtr, pubListPtr, cPubListLen)
}

func sliceToPtr(data []byte) *C.uchar {
	cData := C.CBytes(data)
	cDataPtr := (*C.uchar)(cData)
	return cDataPtr
}

func genRandomBytes(a int) []byte {
	key := make([]byte, a)

	_, err := rand.Read(key)
	if err != nil {
		os.Exit(1)
	}
	return key
}
