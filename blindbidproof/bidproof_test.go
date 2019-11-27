package blindbidproof

import (
	"sync"
	"testing"
	"time"

	ristretto "github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
)

func TestProveVerify(t *testing.T) {
	d := genRandScalar()
	k := genRandScalar()
	seed := genRandScalar()

	// public list of bids
	bidList := make([]ristretto.Scalar, 0, 5)
	for i := 0; i < 5; i++ {
		bidList = append(bidList, genRandScalar())
	}

	proof, err := Prove(d, k, seed, bidList)
	if err != nil {
		panic(err)
	}

	res, err := proof.Verify(seed)
	if err != nil {
		panic(err)
	}

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
		proof, err := Prove(d, k, seed, bidList)
		if err != nil {
			panic(err)
		}

		verify, err := proof.Verify(seed)
		if err != nil {
			panic(err)
		}

		if !verify {
			panic("Verification failed")
		}
	}
}

func Benchmark1ProveNVerifyAsync(b *testing.B) {
	b.ReportAllocs()

	numberOfNodes := 10
	nodes := make([][]ristretto.Scalar, numberOfNodes)
	bids := make([][]ristretto.Scalar, numberOfNodes)
	interval := make([]time.Duration, numberOfNodes)

	// Initialize the nodes
	for i := 0; i < numberOfNodes; i++ {
		nodes[i] = make([]ristretto.Scalar, 3)
		bids[i] = make([]ristretto.Scalar, 5)

		for x := 0; x < 3; x++ {
			nodes[i][x] = genRandScalar()
		}

		for x := 0; x < 5; x++ {
			bids[i][x] = genRandScalar() // Review this
		}

		interval[i] = time.Duration(100*i/numberOfNodes) * time.Millisecond
	}

	var wg sync.WaitGroup

	b.ResetTimer()
	b.N = numberOfNodes * numberOfNodes

	for node := 0; node < numberOfNodes; node++ {
		wg.Add(1)
		go func(node int, interval time.Duration, d ristretto.Scalar, k ristretto.Scalar, seed ristretto.Scalar, bidList []ristretto.Scalar) {
			defer wg.Done()
			time.Sleep(interval)

			proof, err := Prove(d, k, seed, bidList)
			if err != nil {
				panic(err)
			}
			for verify := 0; verify < numberOfNodes; verify++ {
				if verify != node {
					wg.Add(1)
					go func(interval time.Duration, proof *ZkProof, seed ristretto.Scalar) {
						defer wg.Done()

						time.Sleep(interval)
						verify, err := proof.Verify(seed)
						if err != nil {
							panic(err)
						}

						if !verify {
							panic("Verification failed")
						}
					}(interval/16, proof, seed)
				}
			}
		}(node, interval[node], nodes[node][0], nodes[node][1], nodes[node][2], bids[node])
	}

	wg.Wait()
}

func genRandScalar() ristretto.Scalar {
	c := ristretto.Scalar{}
	c.Rand()
	return c
}
