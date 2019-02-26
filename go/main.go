package main

// #cgo LDFLAGS: -L../target/release -lblindbid -framework Security
// #include "./libblindbid.h"
import "C"
import (
	"crypto/rand"
	"fmt"
	"os"
	"time"
	"unsafe"

	ristretto "github.com/bwesterb/go-ristretto"
)

// MIMC_ROUNDS is the number of rounds
// for each mimc hash
const MIMC_ROUNDS = 90

// constants used in MIMC
var constants = genConstants()

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

// Prove creates a zkproof using d,k, seed and pubList
// This will be accessed by the consensus
// This will return the proof as a byte slice
func Prove(d, k, seed ristretto.Scalar, pubList []ristretto.Scalar) []byte {

	// generate intermediate values
	q, x, y, yInv, z := prog(d, k, seed)

	dBytes := d.Bytes()
	kBytes := d.Bytes()
	yBytes := y.Bytes()
	yInvBytes := yInv.Bytes()
	qBytes := q.Bytes()
	zBytes := z.Bytes()
	seedBytes := d.Bytes()

	dPtr := sliceToPtr(dBytes)
	kPtr := sliceToPtr(kBytes)
	yPtr := sliceToPtr(yBytes)
	yInvPtr := sliceToPtr(yInvBytes)
	qPtr := sliceToPtr(qBytes)
	zPtr := sliceToPtr(zBytes)
	seedPtr := sliceToPtr(seedBytes)

	// shuffle x in slice
	pubList, index := Shuffle(x, pubList)

	pL := make([]byte, 0, 32*len(pubList))
	for i := 0; i < 8; i++ {
		pL = append(pL, pubList[i].Bytes()...)
	}

	pubListBuff := C.struct_Buffer{
		ptr: sliceToPtr(pL),
		len: C.size_t(len(pL)),
	}

	C.prove(dPtr, kPtr, yPtr, yInvPtr, qPtr, zPtr, seedPtr, &pubListBuff, index)
	// Takr result from C.prove and make it into one big byte slice

	return nil
}

//Shuffle will shuffle the x value in the slice
// returning the index of the newly shuffled item and the slice
func Shuffle(x ristretto.Scalar, vals []ristretto.Scalar) ([]ristretto.Scalar, uint8) {

	var index uint8

	// append x to slice
	vals = append(vals, x)

	r := rand.New(rand.NewSource(time.Now().Unix()))

	ret := make([]ristretto.Scalar, len(vals))
	perm := r.Perm(len(vals))
	for i, randIndex := range perm {
		ret[i] = vals[randIndex]
		if ret[i].Equals(&x) {
			index = uint8(i)
		}
	}
	return ret, index
}

// genConstants will generate the constants for
// MIMC rounds
func genConstants() []ristretto.Scalar {
	constants := make([]ristretto.Scalar, MIMC_ROUNDS)
	var seed = []byte("blind bid")
	for i := 0; i < len(constants); i++ {
		c := ristretto.Scalar{}
		c.Derive(seed)
		constants[i] = c
		seed = c.Bytes()
	}
	return constants
}

func prog(d, k, seed ristretto.Scalar) (ristretto.Scalar, ristretto.Scalar, ristretto.Scalar, ristretto.Scalar, ristretto.Scalar) {

	zero := ristretto.Scalar{}
	zero.SetZero()

	m := mimc_hash(k, zero)

	x := mimc_hash(d, m)

	y := mimc_hash(seed, x)

	yInv := ristretto.Scalar{}
	yInv.Inverse(&y)

	z := mimc_hash(seed, m)

	q := ristretto.Scalar{}
	q.Mul(&d, &yInv)

	return q, x, y, yInv, z
}
