// Package zkproof contains the Go APIs to generate and verify
// a zero-knownledge prove for the Dusk's Blind Bid.
//
// Under the hood is using named pipes for a fast IPC with the Blind Bid
// process.
//
// A concrete implementation of the Blind Bid can be found here:
// https://gitlab.dusk.network/dusk-core/blindbidproof
package zkproof

import (
	"bufio"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	ristretto "github.com/bwesterb/go-ristretto"
)

// ZkProof holds all of the returned values from a generated proof.
type ZkProof struct {
	Proof         []byte
	Score         []byte
	Z             []byte
	BinaryBidList []byte
}

// The number of rounds or each mimc hash
const mimcRounds = 90

// constants used in MIMC
var constants = genConstants()

// Creates a new `NamedPipe` using a blocking FIFO named "pipe-channel" in the
// OS' temporary folder
var pipe = NewNamedPipe(tempFilePath("pipe-channel"))

// Since the named pipe is blocking, we need a buffered writer
var bufferedPipeWriter = bufio.NewWriter(&pipe)

// Prove creates a zkproof using `d`, `k`, `seed` and `pubList`, and returns
// a ZkProof data type.
func Prove(d, k, seed ristretto.Scalar, bidList []ristretto.Scalar) ZkProof {
	// generate intermediate values
	q, x, y, yInv, z := prog(d, k, seed)

	// shuffle x in slice
	bidList, i := shuffle(x, bidList)

	bL := make([]byte, 0, 32*len(bidList))
	for i := 0; i < len(bidList); i++ {
		bL = append(bL, bidList[i].Bytes()...)
	}

	bw := NewBinWriter(bufferedPipeWriter)
	// set opcode
	bw.Write(uint8(1)) // Prove
	// set payload
	bw.VarWrite(d.Bytes())
	bw.VarWrite(k.Bytes())
	bw.VarWrite(y.Bytes())
	bw.VarWrite(yInv.Bytes())
	bw.VarWrite(q.Bytes())
	bw.VarWrite(z.Bytes())
	bw.VarWrite(seed.Bytes())
	bw.VarWrite(bL)
	bw.Write(uint8(i))

	// write to pipe
	if err := bufferedPipeWriter.Flush(); err != nil {
		panic(err)
	}

	// read the result from the pipe
	bytes, err := pipe.ReadAll()
	if err != nil {
		panic(err)
	}

	return ZkProof{
		Proof:         bytes,
		Score:         q.Bytes(),
		Z:             z.Bytes(),
		BinaryBidList: bL,
	}
}

// Verify a ZkProof using the provided seed.
// Returns `true` or `false` depending on whether it is successful.
func (proof *ZkProof) Verify(seed ristretto.Scalar) bool {
	bw := NewBinWriter(bufferedPipeWriter)
	// set opcode
	bw.Write(uint8(2)) // Verify
	// set payload
	bw.VarWrite(proof.Proof)
	bw.VarWrite(seed.Bytes())
	bw.VarWrite(proof.BinaryBidList)
	bw.VarWrite(proof.Score)
	bw.VarWrite(proof.Z)

	// write to pipeline
	if err := bufferedPipeWriter.Flush(); err != nil {
		panic(err)
	}

	bytes, err := pipe.ReadAll()
	if err != nil {
		panic(err)
	}

	return bytes[0] == 1
}

// CalculateX calculates the blind bid `X`.
func CalculateX(d, m ristretto.Scalar) ristretto.Scalar {
	x := mimcHash(d, m)
	return x
}

// CalculateM calculates `H(k)`.
func CalculateM(k ristretto.Scalar) ristretto.Scalar {
	zero := ristretto.Scalar{}
	zero.SetZero()

	m := mimcHash(k, zero)
	return m
}

// shuffle will shuffle the `x` in the slice given; returning the newly shuffled
// slice, and the `x`'s index.
func shuffle(x ristretto.Scalar, vals []ristretto.Scalar) (
	[]ristretto.Scalar, uint8) {

	var index uint8

	// append x to slice
	values := unique(append(vals, x))

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

// genConstants will generate the constants for MIMC rounds.
// The `seed` is the same used by the Blind Bid concrete implementation, in
// order to have matching constants.
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

func prog(d, k, seed ristretto.Scalar) (
	ristretto.Scalar,
	ristretto.Scalar,
	ristretto.Scalar,
	ristretto.Scalar,
	ristretto.Scalar) {

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

func tempFilePath(name string) string {
	return filepath.Join(os.TempDir(), name)
}

func unique(s []ristretto.Scalar) []ristretto.Scalar {
	seen := make(map[ristretto.Scalar]struct{}, len(s))
	j := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[j] = v
		j++
	}
	return s[:j]
}
