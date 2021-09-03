////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"crypto/rand"
	"testing"
)

func (k *Key) benchComputePK() []byte {
	// Compute secret keys
	points := k.computeSK()

	// Get Hashes
	// PRF
	hPrf := k.params.prfHash.New()

	// Hash buffer
	prfBuffer := make([]byte, 0, hPrf.Size())

	// Compute random elements
	rands := computeRands(k.params.n, k.pSeed, hPrf)

	// Chains memory
	value := make([]byte, k.params.n)

	// Save output values
	outputs := make([]byte, k.params.n * k.params.total)

	// index
	begin := uint8(0)
	end := uint8(W -1)
	for i := 0; i < k.params.total; i++ {
		// Initialize value with the relevant ladder from the signature OR Secret Keys
		copy(value, points[i * k.params.n : (i+1) * k.params.n])

		// Go down the ladder
		for j := begin; j < end; j++ {

			// Perform masking of the value by XORing it with the correct random element
			for z, val := range value {
				value[z] = rands[j][z] ^ val
			}

			// Chain the value. value = H(PKSEED || j || masked value)
			prfBuffer = chain(prfBuffer, hPrf, k.pSeed, j+1, value)
			copy(value, prfBuffer[0:k.params.n])
			prfBuffer = prfBuffer[:0]
		}
		copy(outputs[i * k.params.n : (i+1) * k.params.n], value)
	}
	// PubKey = Public Seed || PK_0 || PK_1 || ... || PK_n-1
	return append(k.pSeed, outputs...)
}

func (p *Params) compressPK(outputs []byte) []byte {
	// Hash outputs directly
	// Compressed PubKey = H(Public Seed || PK_0 || PK_1 || ... || PK_n-1)
	return PKHash.Hash(outputs)
}

func (p *Params) tweak(outputs []byte) []byte {
	// Separate public seed from ladders
	pSeed := outputs[:SeedSize]
	outputs = outputs[SeedSize:]
	// Get tweak hash func
	h := PKHash.New()
	// Compute tweak
	for i := 0 ; i < p.total; i++ {
		if parity(outputs[i * p.n : (i+1) * p.n]) {
			h.Write(outputs[i * p.n : (i+1) * p.n])
		}
	}
	tweak := h.Sum(nil)
	// Tweaked PubKey = H(Public Seed || Tweak || PK_0 || PK_1 || ... || PK_n-1)
	h.Reset()
	h.Write(pSeed)
	h.Write(tweak)
	h.Write(outputs)
	return h.Sum(nil)
}

func BenchmarkTweak_ComputePK(b *testing.B) {
	seed := make([]byte, SeedSize)
	_, _ = rand.Read(seed)
	pSeed := make([]byte, SeedSize)
	_, _ = rand.Read(pSeed)
	key := NewKeyFromSeed(consensusParams, seed, pSeed)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		key.benchComputePK()
	}
}

func BenchmarkTweak_ComputePKCompress(b *testing.B) {
	seed := make([]byte, SeedSize)
	_, _ = rand.Read(seed)
	pSeed := make([]byte, SeedSize)
	_, _ = rand.Read(pSeed)
	key := NewKeyFromSeed(consensusParams, seed, pSeed)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		out := key.benchComputePK()
		consensusParams.compressPK(out)
	}
}

func BenchmarkTweak_ComputePKWithTweak(b *testing.B) {
	seed := make([]byte, SeedSize)
	_, _ = rand.Read(seed)
	pSeed := make([]byte, SeedSize)
	_, _ = rand.Read(pSeed)
	key := NewKeyFromSeed(consensusParams, seed, pSeed)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		out := key.benchComputePK()
		consensusParams.tweak(out)
	}
}
