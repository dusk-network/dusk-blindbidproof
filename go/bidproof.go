package blindbid

import (
	"math/rand"
	"os"
	"path/filepath"
	"time"

	ristretto "github.com/bwesterb/go-ristretto"
)

// The number of rounds or each mimc hash
const mimcRounds = 90

// constants used in MIMC
var constants = genConstants()

var pipePath = tempFilePath("pipe-channel")

// Prove creates a zkproof using d,k, seed and pubList
// This will be accessed by the consensus
// This will return the proof as a byte slice
func Prove(d, k, seed ristretto.Scalar, pubList []ristretto.Scalar) ([]byte, []byte, []byte, []byte) {
	pipe := NamedPipe{Path: pipePath}

	// generate intermediate values
	q, x, y, yInv, z := prog(d, k, seed)

	// shuffle x in slice
	pubList, i := shuffle(x, pubList)

	pL := make([]byte, 0, 32*len(pubList))
	for i := 0; i < len(pubList); i++ {
		pL = append(pL, pubList[i].Bytes()...)
	}

	bytes := BytesArray{}

	// set opcode
	bytes.WriteUint8(1) // Prove
	// set payload
	bytes.Write(d.Bytes())
	bytes.Write(k.Bytes())
	bytes.Write(y.Bytes())
	bytes.Write(yInv.Bytes())
	bytes.Write(q.Bytes())
	bytes.Write(z.Bytes())
	bytes.Write(seed.Bytes())
	bytes.Write(pL)
	bytes.WriteUint8(i)

	// write to pipeline
	if err := pipe.WriteBytes(bytes); err != nil {
		panic(err)
	}

	// read the result
	bytes, err := pipe.ReadBytes()
	if err != nil {
		panic(err)
	}

	// result := C.prove(dPtr, kPtr, yPtr, yInvPtr, qPtr, zPtr, seedPtr, &pubListBuff, &constListBuff, index)

	return bytes.Bytes(), q.Bytes(), z.Bytes(), pL
}

// Verify take a proof in byte format and returns true or false depending on whether
// it is successful
func Verify(proof, seed, pubList, q, zImg []byte) bool {
	pipe := NamedPipe{Path: pipePath}
	bytes := BytesArray{}

	// set opcode
	bytes.WriteUint8(2) // Verify
	// set payload
	bytes.Write(proof)
	bytes.Write(seed)
	bytes.Write(pubList)
	bytes.Write(q)
	bytes.Write(zImg)

	// write to pipeline
	if err := pipe.WriteBytes(bytes); err != nil {
		panic(err)
	}

	// read the result
	bytes, err := pipe.ReadBytes()
	if err != nil {
		panic(err)
	}

	return bytes.Bytes()[0] == 1
}

// CalculateX calculates the blind bid X
func CalculateX(d, k ristretto.Scalar) ristretto.Scalar {
	zero := ristretto.Scalar{}
	zero.SetZero()

	m := mimcHash(k, zero)

	x := mimcHash(d, m)
	return x
}

// CalculateM calculates H(k)
func CalculateM(d, k ristretto.Scalar) ristretto.Scalar {
	zero := ristretto.Scalar{}
	zero.SetZero()

	m := mimcHash(k, zero)
	return m
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
	constants := make([]ristretto.Scalar, mimcRounds)
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

	m := mimcHash(k, zero)

	x := mimcHash(d, m)

	y := mimcHash(seed, x)

	yInv := ristretto.Scalar{}
	yInv.Inverse(&y)

	z := mimcHash(seed, m)

	q := ristretto.Scalar{}
	q.Mul(&d, &yInv)

	return q, x, y, yInv, z
}

func mimcHash(left, right ristretto.Scalar) ristretto.Scalar {
	x := left
	key := right
	a := ristretto.Scalar{}
	a2 := ristretto.Scalar{}
	a3 := ristretto.Scalar{}
	a4 := ristretto.Scalar{}

	for i := 0; i < mimcRounds; i++ {
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

func constantsToBytes(cconstants []ristretto.Scalar) []byte {
	c := make([]byte, 0, 90*32)
	for i := 0; i < len(constants); i++ {
		c = append(c, constants[i].Bytes()...)
	}
	return c
}

func tempFilePath(name string) string {
	return filepath.Join(os.TempDir(), name)
}
