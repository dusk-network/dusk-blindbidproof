package blindbid

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
	pubList := make([]ristretto.Scalar, 0, 5)
	for i := 0; i < 5; i++ {
		pubList = append(pubList, genRandScalar())
	}

	proof, qBytes, zBytes, pL := Prove(d, k, seed, pubList)
	res := Verify(proof, seed.Bytes(), pL, qBytes, zBytes)
	assert.Equal(t, true, res)
	//}
}

func BenchmarkProveVerify(b *testing.B) {

	b.ReportAllocs()

	d := genRandScalar()
	k := genRandScalar()
	seed := genRandScalar()

	// public list of bids
	pubList := make([]ristretto.Scalar, 0, 5)
	for i := 0; i < 5; i++ {
		pubList = append(pubList, genRandScalar())
	}
	b.ResetTimer()
	b.N = 20
	for n := 0; n < b.N; n++ {
		proof, qBytes, zBytes, pL := Prove(d, k, seed, pubList)
		Verify(proof, seed.Bytes(), pL, qBytes, zBytes)
	}
}
