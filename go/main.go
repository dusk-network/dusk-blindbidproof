package main

// #cgo LDFLAGS: -L../target/release -lblindbid -framework Security
// #include "./libblindbid.h"
import "C"
import (
	"crypto/rand"
	"fmt"
	"os"
	"unsafe"
)

func main() {
	d := genRandomBytes(32)
	k := genRandomBytes(32)
	seed := genRandomBytes(32)
	dPtr := sliceToPtr(d)
	kPtr := sliceToPtr(k)
	seedPtr := sliceToPtr(seed)

	x := make([]byte, 32)
	y := make([]byte, 32)
	yInv := make([]byte, 32)
	q := make([]byte, 32)
	zImg := make([]byte, 32)

	xPtr := toPtr(x)
	yPtr := toPtr(y)
	yInvPtr := toPtr(yInv)
	qPtr := toPtr(q)
	zImgPtr := toPtr(zImg)

	C.prog(seedPtr, kPtr, dPtr, qPtr, xPtr, yPtr, yInvPtr, zImgPtr)

	pubList := make([]byte, 0, 32*8)

	for i := 0; i < 7; i++ {
		pubList = append(pubList, genRandomBytes(32)...)
	}
	pubList = append(pubList, x...)

	pubListBuff := C.struct_Buffer{
		ptr: sliceToPtr(pubList),
		len: C.size_t(len(pubList)),
	}

	result := C.prove(dPtr, kPtr, yPtr, yInvPtr, qPtr, zImgPtr, seedPtr, &pubListBuff, 7)

	if result != nil {
		fmt.Printf("%+v\n", result)
		// here we send the same result to verify, ideally since it won't be
		// in the same machine, it would be send over a socket and deallocate
		// promptly.
		verified := C.verify(result, seedPtr, &pubListBuff, qPtr, zImgPtr)
		C.dealloc_proof(result)
		if verified {
			fmt.Print("Verified\n")
		} else {
			fmt.Print("Verification failed\n")
			os.Exit(1)
		}
	} else {
		os.Exit(1)
	}
}

func toPtr(data []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&data[0]))
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
