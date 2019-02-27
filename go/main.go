package main

import (
	"fmt"

	ristretto "github.com/bwesterb/go-ristretto"
)

func main() {

	// amount in the bidding transaction
	d := genRandScalar()
	// secret number
	k := genRandScalar()
	// seed from block
	seed := genRandScalar()

	// public list of bids
	pubList := make([]ristretto.Scalar, 0, 5)
	for i := 0; i < 5; i++ {
		pubList = append(pubList, genRandScalar())
	}

	wrongpL := make([]byte, 0, 32*len(pubList))
	for i := 0; i < len(pubList)+1; i++ {
		s := genRandScalar()
		wrongpL = append(wrongpL, s.Bytes()...)
	}

	proof, qBytes, zBytes, _ := Prove(d, k, seed, pubList)

	fmt.Printf("Score is %d \n", qBytes)
	fmt.Printf("Z is %d \n", zBytes)
	fmt.Printf("proof is %d \n", zBytes)

	res := Verify(proof, seed.Bytes(), wrongpL, qBytes, zBytes)
	fmt.Println(res)
}

func genRandScalar() ristretto.Scalar {
	c := ristretto.Scalar{}
	c.Rand()
	return c
}
