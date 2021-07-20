////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"crypto/rand"
	"github.com/xx-labs/sleeve/hasher"
	"testing"
)

func getRandData(t *testing.T, size int) []byte {
	data := make([]byte, size)
	n, err := rand.Read(data)

	if err != nil {
		t.Fatalf("Error reading random bytes: %s", err)
	}

	if n != size {
		t.Fatalf("Reader only gave us %d bytes, expected %d", n, size)
	}
	return data
}

func TestParams_NewParams(t *testing.T) {
	// Test message size being 0
	params := NewParams(32, 0, hasher.BLAKE3_256, hasher.BLAKE3_256)

	if params != nil {
		t.Fatalf("NewParams() should return nil if message size is 0!")
	}

	// Test message size larger than allowed
	params = NewParams(32, MaxMsgSize+1, hasher.BLAKE3_256, hasher.BLAKE3_256)

	if params != nil {
		t.Fatalf("NewParams() should return nil if message size is greater than %d!", MaxMsgSize)
	}

	// Test PRF hash size smaller than n
	params = NewParams(32, 32, hasher.SHA3_224, hasher.BLAKE3_256)

	if params != nil {
		t.Fatalf("NewParams() should return nil if PRF hash size is smaller than n")
	}

	// Test MSG hash size smaller than m
	params = NewParams(32, 32, hasher.BLAKE3_256, hasher.SHA3_224)

	if params != nil {
		t.Fatalf("NewParams() should return nil if MSG hash size is smaller than m")
	}

	// Test one checksum ladder
	params = NewParams(32, 1, hasher.BLAKE3_256, hasher.BLAKE3_256)

	if params.total != 2 {
		t.Fatalf("Checksum size should be 1 if message size is 1. Got %d instead", params.total-1)
	}

	// Test two checksum ladders
	params = NewParams(32, 2, hasher.BLAKE3_256, hasher.BLAKE3_256)

	if params.total != 4 {
		t.Fatalf("Checksum size should be 2 if message size is greater than 1. Got %d instead", params.total-2)
	}
}

func TestParams_String(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)

	expected := "N: 32, M: 32, PRF: BLAKE3_256, MSG: BLAKE3_256"

	str := params.String()

	if str != expected {
		t.Errorf("Params.String() returned invalid string! Expected %s, got %s", expected, str)
	}
}

func TestParams_Equal(t *testing.T) {
	// Test params equality
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)

	// Different n
	other := NewParams(28, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	if params.Equal(other) {
		t.Fatalf("Params can't be equal when n is different")
	}

	// Different m
	other = NewParams(32, 28, hasher.BLAKE3_256, hasher.BLAKE3_256)
	if params.Equal(other) {
		t.Fatalf("Params can't be equal when m is different")
	}

	// Different PRF Hash
	other = NewParams(32, 32, hasher.BLAKE2B_256, hasher.BLAKE3_256)
	if params.Equal(other) {
		t.Fatalf("Params can't be equal when PRF hash is different")
	}

	// Different MSG Hash
	other = NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE2B_256)
	if params.Equal(other) {
		t.Fatalf("Params can't be equal when MSG hash is different")
	}

	// Equal params
	other = NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	if !params.Equal(other) {
		t.Fatalf("Params should be equal")
	}
}

func TestParams_Decode(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)

	// 32 ladders + 2 checksum ladders + public seed, all of 32 bytes
	sigLen := (32 + 2) * 32 + 32

	// Get a random signature
	sig := getRandData(t, sigLen)

	// Get a random message
	msg := getRandData(t, 256)

	// Test valid decoding
	ret := make([]byte, 0, PKSize)
	var err error
	ret, err = params.Decode(ret, msg, sig)

	if ret == nil || err != nil {
		t.Fatalf("Params.Decode() returned (nil, error) but signature had correct size!")
	}

	// Test decoding a small signature
	ret = ret[:0]
	ret, err = params.Decode(ret, msg, sig[0:sigLen-2])

	if ret != nil || err == nil {
		t.Fatalf("Params.Decode() should have returned (nil, error) for small signature. Got %v instead", ret)
	}

	// Test decoding a large signature
	ret = ret[:0]
	ret, err = params.Decode(ret, msg, append(msg, sig...))

	if ret != nil || err == nil {
		t.Fatalf("Params.Decode() should have returned (nil, error) for large signature. Got %v instead", ret)
	}

	// Test nil output slice
	ret, err = params.Decode(nil, msg, sig)

	if ret != nil || err == nil {
		t.Fatalf("Params.Decode() should have returned (nil, error) when output slice is nil. Got %v instead", ret)
	}

	// Test sized output slice
	ret = make([]byte, PKSize)
	ret, err = params.Decode(ret, msg, sig)

	if ret != nil || err == nil {
		t.Fatalf("Params.Decode() should have returned (nil, error) when output slice is not empty. Got %v instead", ret)
	}

	// Test wrong capacity output slice
	ret = make([]byte, 0, PKSize-2)
	ret, err = params.Decode(ret, msg, sig)

	if ret != nil || err == nil {
		t.Fatalf("Params.Decode() should have returned (nil, error) when output slice doesn't have enough capacity." +
			" Got %v instead", ret)
	}
}

func TestParams_Verify(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)

	// 32 ladders + 2 checksum ladders + public seed, all of 32 bytes
	sigLen := (32 + 2) * 32 + 32

	// Get a random signature
	sig := getRandData(t, sigLen)

	// Get a random message
	msg := getRandData(t, 256)

	// Get a random public key
	pk := getRandData(t, PKSize)

	// Test valid arguments verify, with random public key (verification returns false)
	valid, err := params.Verify(msg, sig, pk)

	if err != nil {
		t.Fatalf("Params.Verify() returned error when all arguments are well formed")
	}

	if valid {
		t.Fatalf("Params.Verify() returned true for random signature and public key")
	}

	// Test invalid public key size
	pk = getRandData(t, PKSize-4)
	_, err = params.Verify(msg, sig, pk)

	if err == nil {
		t.Fatalf("Params.Verify() should return error when public key has incorrect size")
	}
}
