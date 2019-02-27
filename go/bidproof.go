package main

// #cgo LDFLAGS: -L../target/release -lblindbid -framework Security
// #include "./libblindbid.h"
import "C"
import (
	"bytes"
	"fmt"
	"math/rand"
	"time"
	"unsafe"

	"github.com/CityOfZion/neo-go/pkg/wire/util"
	ristretto "github.com/bwesterb/go-ristretto"
)

// MIMC_ROUNDS is the number of rounds
// for each mimc hash
const MIMC_ROUNDS = 90

// constants used in MIMC
var constants = genConstants()

// Prove creates a zkproof using d,k, seed and pubList
// This will be accessed by the consensus
// This will return the proof as a byte slice
func Prove(d, k, seed ristretto.Scalar, pubList []ristretto.Scalar) ([]byte, []byte, []byte, []byte) {

	// generate intermediate values
	q, x, y, yInv, z := prog(d, k, seed)

	dBytes := d.Bytes()
	kBytes := k.Bytes()
	yBytes := y.Bytes()
	yInvBytes := yInv.Bytes()
	qBytes := q.Bytes()
	zBytes := z.Bytes()
	seedBytes := seed.Bytes()

	dPtr := toPtr(dBytes)
	kPtr := toPtr(kBytes)
	yPtr := toPtr(yBytes)
	yInvPtr := toPtr(yInvBytes)
	qPtr := toPtr(qBytes)
	zPtr := toPtr(zBytes)
	seedPtr := toPtr(seedBytes)

	// shuffle x in slice
	pubList, i := shuffle(x, pubList)
	index := C.uint8_t(i)

	pL := make([]byte, 0, 32*len(pubList))
	for i := 0; i < len(pubList); i++ {
		pL = append(pL, pubList[i].Bytes()...)
	}

	pubListBuff := C.struct_Buffer{
		ptr: sliceToPtr(pL),
		len: C.size_t(len(pL)),
	}

	con := constantsToBytes(constants)

	constListBuff := C.struct_Buffer{
		ptr: sliceToPtr(con),
		len: C.size_t(len(con)),
	}

	result := C.prove(dPtr, kPtr, yPtr, yInvPtr, qPtr, zPtr, seedPtr, &pubListBuff, &constListBuff, index)
	data := proofToBytes(*result)

	return data, q.Bytes(), z.Bytes(), pL
}

// Verify take a proof in byte format and returns true or false depending on whether
// it is successful
func Verify(proof, seed, pubList, q, zImg []byte) bool {
	pBuf := bytesToProof(proof)

	qPtr := toPtr(q)
	zImgPtr := toPtr(zImg)
	seedPtr := sliceToPtr(seed)

	pubListBuff := C.struct_Buffer{
		ptr: sliceToPtr(pubList),
		len: C.size_t(len(pubList)),
	}

	con := constantsToBytes(constants)

	constListBuff := C.struct_Buffer{
		ptr: sliceToPtr(con),
		len: C.size_t(len(con)),
	}

	verified := C.verify(&pBuf, seedPtr, &pubListBuff, qPtr, zImgPtr, &constListBuff)

	if verified {
		fmt.Println("This is Verified!")
		return true
	}

	fmt.Println("Verify fail")

	return false
}

//Shuffle will shuffle the x value in the slice
// returning the index of the newly shuffled item and the slice
func shuffle(x ristretto.Scalar, vals []ristretto.Scalar) ([]ristretto.Scalar, uint8) {

	var index uint8

	// append x to slice
	values := append(vals, x)

	r := rand.New(rand.NewSource(time.Now().Unix()))

	ret := make([]ristretto.Scalar, len(values))
	perm := r.Perm(len(values))
	for i, randIndex := range perm {
		ret[i] = values[randIndex]
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

func mimc_hash(left, right ristretto.Scalar) ristretto.Scalar {
	x := left
	key := right

	for i := 0; i < MIMC_ROUNDS; i++ {
		a := ristretto.Scalar{}
		a2 := ristretto.Scalar{}
		a3 := ristretto.Scalar{}
		a4 := ristretto.Scalar{}

		// a = x + key + constants[i]
		a.Add(&x, &key).Add(&a, &constants[i])

		// a^2
		a2.Square(&a)

		// a ^3
		a3.Mul(&a2, &a)

		//a^4
		a4.Mul(&a3, &a)

		// a_7
		x.Mul(&a4, &a3)
	}

	x.Add(&x, &key)

	return x

}

func proofToBytes(pBuf C.struct_ProofBuffer) []byte {

	buf := &bytes.Buffer{}
	bw := BinWriter{W: buf}

	proof := bufferToBytes(pBuf.proof)
	bw.VarBytes(proof)

	commitments := bufferToBytes(pBuf.commitments)
	bw.VarBytes(commitments)

	toggleComm := bufferToBytes(pBuf.t_c)
	bw.VarBytes(toggleComm)

	return buf.Bytes()
}

func bytesToProof(b []byte) C.struct_ProofBuffer {

	r := bytes.NewReader(b)
	br := &util.BinReader{R: r}

	proof := br.VarBytes()

	proofBuff := C.struct_Buffer{
		ptr: sliceToPtr(proof),
		len: C.size_t(len(proof)),
	}

	commitments := br.VarBytes()

	commBuff := C.struct_Buffer{
		ptr: sliceToPtr(commitments),
		len: C.size_t(len(commitments)),
	}
	toggleComm := br.VarBytes()

	toggleBuff := C.struct_Buffer{
		ptr: sliceToPtr(toggleComm),
		len: C.size_t(len(toggleComm)),
	}

	pBuf := C.struct_ProofBuffer{
		proof:       proofBuff,
		commitments: commBuff,
		t_c:         toggleBuff,
	}

	return pBuf
}

func bufferToBytes(buf C.struct_Buffer) []byte {
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
}

func constantsToBytes(cconstants []ristretto.Scalar) []byte {
	c := make([]byte, 0, 90*32)
	for i := 0; i < len(constants); i++ {
		c = append(c, constants[i].Bytes()...)
	}
	return c
}
