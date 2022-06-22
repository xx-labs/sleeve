////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wallet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/tyler-smith/go-bip39"
	"github.com/xx-labs/sleeve/hasher"
	"github.com/xx-labs/sleeve/wots"
	"testing"
)

type ErrReader struct{}

func (r *ErrReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("TEST")
}

type LimitedReader struct {
	limit int
}

func (r *LimitedReader) Read(p []byte) (n int, err error) {
	if r.limit > len(p) {
		r.limit -= len(p)
		return len(p), nil
	}
	return r.limit, nil
}

func TestNewSleeve(t *testing.T) {
	// Test with error reader
	_, err := NewSleeve(&ErrReader{}, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeve() should return error when there's an error reading entropy")
	}

	// Test with limited bytes reader
	_, err = NewSleeve(&LimitedReader{EntropySize / 2}, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeve() should return error when there's an error reading enough bytes of entropy")
	}
}

func TestNewSleeveFromEntropy(t *testing.T) {
	// Test wrong entropy size (31 bytes)
	ent := make([]byte, EntropySize-1)

	_, err := NewSleeveFromEntropy(ent, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeveFromEntropy() should return error when provided entropy doesn't meet BIP39 standard")
	}

	// Test valid BIP39 entropy size (16 bytes), but not enough for Sleeve
	ent = make([]byte, EntropySize/2)

	_, err = NewSleeveFromEntropy(ent, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeveFromEntropy() should return error when provided entropy is of incorrect size")
	}
}

func TestNewSleeveFromMnemonic(t *testing.T) {
	// Test mnemonic with less than 24 words
	randMnem := "one two three xx    network   sleeve implementation"

	_, err := NewSleeveFromMnemonic(randMnem, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeveFromMnemonic() should return error when provided mnemonic has invalid number of words")
	}

	// Test mnemonic with 24 words but one invalid word
	invalidWordMnem := "armed output survey rent myself sentence warm eyebrow scan isolate thunder point" +
		" bulk skirt sketch bird palm sleep dash jazz list behave spin xxnetwork"

	_, err = NewSleeveFromMnemonic(invalidWordMnem, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeveFromMnemonic() should return error when provided mnemonic has an invalid work")
	}

	// Test mnemonic with 24 words but invalid checksum
	invalidChkMnem := "armed output survey rent myself sentence warm eyebrow scan isolate thunder point" +
		" bulk skirt sketch bird palm sleep dash jazz list behave spin spin"

	_, err = NewSleeveFromMnemonic(invalidChkMnem, "", DefaultGenSpec())

	if err == nil {
		t.Fatalf("NewSleeveFromMnemonic() should return error when provided mnemonic has incorrect checksum")
	}
}

func TestNewSleeveWithGenSpec(t *testing.T) {
	// Test valid spec
	spec := GenSpec{
		account: 1992,
		params:  wots.Level3,
	}

	_, err := NewSleeve(rand.Reader, "", spec)

	if err != nil {
		t.Fatalf("NewSleeve() shouldn't return error in valid generation")
	}

	// Test invalid account
	spec = GenSpec{
		account: firstHardened,
		params:  wots.Level3,
	}

	_, err = NewSleeve(rand.Reader, "", spec)

	if err == nil {
		t.Fatalf("NewSleeve() shouldn return error when desired account is invalid")
	}

	// Test invalid wots params
	spec = GenSpec{
		account: 1992,
		params:  wots.ParamsEncodingLen,
	}

	_, err = NewSleeve(rand.Reader, "", spec)

	if err == nil {
		t.Fatalf("NewSleeve() shouldn return error when WOTS+ params encoding is invalid")
	}
}

func TestSleeve_Getters(t *testing.T) {
	// Test valid Sleeve and getters
	sleeve, err := NewSleeve(rand.Reader, "", DefaultGenSpec())

	if err != nil {
		t.Fatalf("NewSleeve() shouldn't return error in valid generation")
	}

	if sleeve.GetMnemonic() == "" {
		t.Fatalf("GetMnemonic() returned empty string after Sleeve generation")
	}

	if sleeve.GetOutputMnemonic() == "" {
		t.Fatalf("GetOutputMnemonic() returned empty string after Sleeve generation")
	}
}

// Test vector taken from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
const (
	testVectorEntropy  = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"
	testVectorMnemonic = "hamster diagram private dutch cause delay private meat slide toddler razor book" +
		" happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
	testVectorSeed         = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"
	expectedOutputMnemonic = "speed bar erosion clog exist siren giraffe liar sick hire lazy disagree pig monitor loan owner solve grant excess drop broom render roast primary"
)

func TestSleeve_TestVector(t *testing.T) {
	// Test Sleeve with provided test vector mnemonic
	sleeve, err := NewSleeveFromMnemonic(testVectorMnemonic, "", DefaultGenSpec())

	if err != nil {
		t.Fatalf("NewSleeveFromMnemonic() shouldn't return error in valid generation")
	}

	// Validate output mnemonic is correct
	if sleeve.GetOutputMnemonic() != expectedOutputMnemonic {
		t.Fatalf("Sleeve generation is broken! GetOutputMnemonic() returned wrong mnemonic. Got: %s\nExpected: %s\n",
			sleeve.GetOutputMnemonic(), expectedOutputMnemonic)
	}
}

func TestSleeve_Consistency(t *testing.T) {
	// Test Sleeve with provided test vector
	ent, _ := hex.DecodeString(testVectorEntropy)
	sleeve, err := NewSleeveFromEntropy(ent, "TREZOR", DefaultGenSpec())

	if err != nil {
		t.Fatalf("NewSleeveFromEntropy() shouldn't return error in valid generation")
	}

	// Validate mnemonic is correct
	if sleeve.GetMnemonic() != testVectorMnemonic {
		t.Fatalf("Consistency violation! GetMnemonic() returned wrong mnemonic. Got: %s\nExpected: %s\n",
			sleeve.GetMnemonic(), testVectorMnemonic)
	}

	// Manually derive Sleeve from test seed and prove consistency
	seed, _ := hex.DecodeString(testVectorSeed)
	// Path = m/44'/1955'/0'/0'/0'
	n, _ := ComputeNode(seed, []uint32{0x8000002C, 0x800007A3, 0x80000000, 0x80000000, 0x80000000})
	wotsKey := wots.NewKeyFromSeed(wots.DecodeParams(wots.DefaultParams), n.Key, n.Code)
	pk := wotsKey.ComputePK()

	key := hasher.SHA3_256.Hash(append([]byte("xx network sleeve"), n.Key...))
	outEnt := hasher.SHA3_256.Hash(append(key, pk...))
	outMnem, _ := bip39.NewMnemonic(outEnt)

	// Compare output mnemonic
	if sleeve.GetOutputMnemonic() != outMnem {
		t.Fatalf("Consistency violation! GetOutputMnemonic() returned wrong output mnemonic."+
			" Got: %s\nExpected: %s\n", sleeve.GetOutputMnemonic(), outMnem)
	}
}

const (
	wotsTestVectorMnemonic = "hole define scout taxi help project army vocal sudden wealth volume fan pigeon raven hen spoil cup because crowd wage awkward public reform pluck"
	wotsExpectedPubKeyHex  = "7bd49cdc5f70766c70c973a2d6c76b964333ac853c5ae8ecbfef5f1fde08705a"
)

func TestSleeve_WOTSTestVector(t *testing.T) {
	// Derive WOTS key from test vector mnemonic
	seed, err := bip39.NewSeedWithErrorChecking(wotsTestVectorMnemonic, "")
	if err != nil {
		t.Fatalf("NewSeedWithErrorChecking returned error with valid mnemonic")
	}

	// Path = m/44'/1955'/0'/0'/0'
	n, _ := ComputeNode(seed, []uint32{0x8000002C, 0x800007A3, 0x80000000, 0x80000000, 0x80000000})
	wotsKey := wots.NewKeyFromSeed(wots.DecodeParams(wots.DefaultParams), n.Key, n.Code)
	pk := wotsKey.ComputePK()

	// Validate WOTS PK is correct
	expectedPk, _ := hex.DecodeString(wotsExpectedPubKeyHex)
	if !bytes.Equal(pk, expectedPk) {
		t.Fatalf("WOTS+ generation is broken! ComputePK() returned wrong public key. Got: %x\nExpected: %x\n",
			pk, expectedPk)
	}
}
