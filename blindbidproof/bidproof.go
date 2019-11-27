// Package zkproof contains the Go APIs to generate and verify
// a zero-knownledge prove for the Dusk's Blind Bid.
//
// Under the hood is using named pipes for a fast IPC with the Blind Bid
// process.
//
// A concrete implementation of the Blind Bid can be found here:
// https://gitlab.dusk.network/dusk-core/blindbidproof
package blindbidproof

import (
	"bytes"
    "encoding/binary"
    "errors"
	"math/rand"
	"time"

	ristretto "github.com/bwesterb/go-ristretto"
    "github.com/dusk-network/dusk-tlv/dusk-go-tlv"
)

// ZkProof holds all of the returned values from a generated proof.
type ZkProof struct {
	Proof         []byte
	Score         []byte
	Z             []byte
	BinaryBidList [][]byte
}

// The number of rounds or each mimc hash
const mimcRounds = 90

// constants used in MIMC
var constants = genConstants()

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

// Prove creates a zkproof using `d`, `k`, `seed` and `pubList`, and returns
// a ZkProof data type.
func Prove(d, k, seed ristretto.Scalar, bidList []ristretto.Scalar) (*ZkProof, error) {
	// generate intermediate values
	q, x, y, yInv, z := prog(d, k, seed)

	// shuffle x in slice
	bidList, i := shuffle(x, bidList)

	bL := make([][]byte, 0, len(bidList))
	for i := 0; i < len(bidList); i++ {
		bL = append(bL, bidList[i].Bytes())
	}

    toggleBuf := make([]byte, 8)
    binary.LittleEndian.PutUint64(toggleBuf, uint64(i))

    // create the tlv buffer
	buf := bytes.NewBuffer([]byte{})
	bufTlv := tlv.NewWriter(buf)

	// set opcode
	buf.Write([]byte{0x01}) // Prove

	// set payload
	bufTlv.Write(d.Bytes())
	bufTlv.Write(k.Bytes())
	bufTlv.Write(y.Bytes())
	bufTlv.Write(yInv.Bytes())
	bufTlv.Write(q.Bytes())
	bufTlv.Write(z.Bytes())
	bufTlv.Write(seed.Bytes())
	bufTlv.WriteList(bL)
	bufTlv.Write(toggleBuf)

	// Prepare the socket
	socket, err := createSocket("")
	if err != nil {
        return nil, err
	}
	defer socket.Close()

	// Send the buffered data to the socket
	bs := tlv.NewWriter(socket)
    _, err = bs.Write(buf.Bytes())
	if err != nil {
        return nil, err
	}

	// Read the reply
	reply, err := tlv.ReaderToBytes(socket)
	if err != nil {
        return nil, err
	}

    zk := ZkProof{
		Proof:         reply,
		Score:         q.Bytes(),
		Z:             z.Bytes(),
		BinaryBidList: bL,
	}

	return &zk, nil
}

// Verify a ZkProof using the provided seed.
// Returns `true` or `false` depending on whether it is successful.
func (proof *ZkProof) Verify(seed ristretto.Scalar) (bool, error) {
    // create the tlv buffer
	buf := bytes.NewBuffer([]byte{})
	bufTlv := tlv.NewWriter(buf)

	// set opcode
	buf.Write([]byte{0x02}) // Verify

	// set payload
	bufTlv.Write(proof.Proof)
	bufTlv.Write(proof.Score)
	bufTlv.Write(proof.Z)
	bufTlv.Write(seed.Bytes())
	bufTlv.WriteList(proof.BinaryBidList)

	// Prepare the socket
	socket, err := createSocket("")
	if err != nil {
        return false, err
	}
	defer socket.Close()

	// Send the buffered data to the socket
	bs := tlv.NewWriter(socket)
    _, err = bs.Write(buf.Bytes())
	if err != nil {
        return false, err
	}

	// Read the reply
	reply, err := tlv.ReaderToBytes(socket)
	if err != nil {
        return false, err
	}

    // Sanity check for the reply
    if len(reply) != 1 {
        return false, errors.New("The blindbid reply is not consistent")
    }

	return reply[0] == 1, nil
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
