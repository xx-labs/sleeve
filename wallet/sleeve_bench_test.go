package wallet

import (
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/xx-labs/sleeve/wots"
	"testing"
)

func generateECDSAFromPriv(priv []byte) {
	_, err := crypto.ToECDSA(priv)
	if err != nil {
		panic(err)
	}
}

func generateWOTSKey(seed, pSeed []byte) {
	wotsKey := wots.NewKeyFromSeed(wots.DecodeParams(wots.DefaultParams), seed, pSeed)
	// Force computation of WOTS PK
	_ = wotsKey.ComputePK()
}

func generateSleeveECDSA(seed, pSeed []byte) {
	generateECDSAFromPriv(generateSleeve(seed, pSeed, wots.DecodeParams(wots.DefaultParams)))
}

func BenchmarkSleeve_GenerateECDSA(b *testing.B) {
	priv := make([]byte, 32)
	_, _ = rand.Read(priv)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		generateECDSAFromPriv(priv)
	}
}

func BenchmarkSleeve_GenerateWOTS(b *testing.B) {
	seed := make([]byte, wots.SeedSize)
	_, _ = rand.Read(seed)
	pSeed := make([]byte, wots.SeedSize)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		generateWOTSKey(seed, pSeed)
	}
}

func BenchmarkSleeve_GenerateSleeve(b *testing.B) {
	seed := make([]byte, wots.SeedSize)
	_, _ = rand.Read(seed)
	pSeed := make([]byte, wots.SeedSize)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		generateSleeveECDSA(seed, pSeed)
	}
}
