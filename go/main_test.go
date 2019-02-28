package main

import (
	"testing"

	ristretto "github.com/bwesterb/go-ristretto"
)

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
	for n := 0; n < b.N; n++ {

		proof, qBytes, zBytes, pL := Prove(d, k, seed, pubList)
		Verify(proof, seed.Bytes(), pL, qBytes, zBytes)
	}
}
