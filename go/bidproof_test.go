package zkproof

import (
	"testing"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
)

func TestProveVerify(t *testing.T) {
	//for n := 0; n < 20; n++ {
	d := genRandScalar()
	k := genRandScalar()
	seed := genRandScalar()

	// public list of bids
	bidList := make([]ristretto.Scalar, 0, 5)
	for i := 0; i < 5; i++ {
		bidList = append(bidList, genRandScalar())
	}

	proof := Prove(d, k, seed, bidList)
	res := proof.Verify(seed)
	assert.Equal(t, true, res)
}
func BenchmarkProveVerify(b *testing.B) {
	b.ReportAllocs()

	d := genRandScalar()
	k := genRandScalar()
	seed := genRandScalar()

	// public list of bids
	bidList := make([]ristretto.Scalar, 0, 5)
	for i := 0; i < 5; i++ {
		bidList = append(bidList, genRandScalar())
	}
	b.ResetTimer()
	b.N = 20
	for n := 0; n < b.N; n++ {
		proof := Prove(d, k, seed, bidList)
		proof.Verify(seed)
	}
}

func genRandScalar() ristretto.Scalar {
	c := ristretto.Scalar{}
	c.Rand()
	return c
}
