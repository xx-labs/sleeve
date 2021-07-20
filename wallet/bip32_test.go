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
	"math/big"
	"testing"
)

func TestNewMasterNode(t *testing.T) {
	// Test smaller and larger seeds than allowed
	smallSeed := make([]byte, 4)

	_, err := NewMasterNode(smallSeed)

	if err == nil {
		t.Fatalf("NewMasterNode() should return error when seed is too small")
	}

	largeSeed := make([]byte, 128)

	_, err = NewMasterNode(largeSeed)

	if err == nil {
		t.Fatalf("NewMasterNode() should return error when seed is too large")
	}

	seed := make([]byte, 64)
	_, _ = rand.Read(seed)

	n, err := NewMasterNode(seed)

	if err != nil {
		t.Fatalf("NewMasterNode() returned error, only possible if key is 0, the universe must have died by now...")
	}

	if len(n.Key) != keySize {
		t.Fatalf("NewMasterNode(): generated key has incorrect size. Got %d, expected %d", len(n.Key), keySize)
	}

	if len(n.Code) != keySize {
		t.Fatalf("NewMasterNode(): generated code has incorrect size. Got %d, expected %d", len(n.Code), keySize)
	}
}

func TestNode_ComputeChild(t *testing.T) {
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)

	n, _ := NewMasterNode(seed)

	// Save key and code
	key := make([]byte, keySize)
	copy(key, n.Key)
	code := make([]byte, keySize)
	copy(code, n.Code)

	// Test compute child fails if index is not for a hardened child
	err := n.ComputeHardenedChild(0)

	if err == nil {
		t.Fatalf("ComputeHardenedChild() should return error for soft derivation indexes")
	}

	// Compute child and confirm key and code changed
	err = n.ComputeHardenedChild(firstHardened)

	if err != nil {
		t.Fatalf("ComputeHardenedChild() returned error, only possible if key is 0, the universe must have died by now...")
	}

	// Confirm key and code changed
	if bytes.Equal(key, n.Key) {
		t.Fatalf("ComputeHardenedChild(): key remained unchanged after function call")
	}

	if bytes.Equal(code, n.Code) {
		t.Fatalf("ComputeHardenedChild(): code remained unchanged after function call")
	}
}

func Test_validateKeyNotZero(t *testing.T) {
	// Check if key being zero is caught
	zero := big.NewInt(0)
	err := validateKeyNotZero(zero)
	if err == nil {
		t.Fatalf("validateKeyNotZero() should return error if key is zero")
	}
}

func Test_validatePrivateKey(t *testing.T) {
	// Check if key being zero is caught
	err := validatePrivateKey(nil)
	if err == nil {
		t.Fatalf("validatePrivateKey() should return error if key is zero")
	}

	// Check if key being greater than N is caught
	key, _ := hex.DecodeString(hexN)
	key[len(key)-1] |= 0xFF
	err = validatePrivateKey(key)
	if err == nil {
		t.Fatalf("validatePrivateKey() should return error if key is larger than N")
	}
}

// Test Vectors
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// Base58 vectors were decoded into hex strings to avoid unnecessary dependency on a base58 library
const (
	vectorOneSeed       = "000102030405060708090a0b0c0d0e0f"
	vectorOneMaster     = "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35e77e9d71"
	vectorOneHardZero   = "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea0a794dec"
	vectorTwoSeed       = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	vectorTwoMaster     = "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e61e16479"
	vectorThreeSeed     = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
	vectorThreeMaster   = "0488ade400000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae3233c0c6bf"
	vectorThreeHardZero = "0488ade40141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd00491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef7332bb35"
)

// Extract chain code and private key from test vector
// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
// 32 bytes: the chain code
// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
const (
	chainCodeStart = 13
	privKeyStart = chainCodeStart + keySize + 1
)
func extractNode(testVectorHex string) *Node {
	decoded, err := hex.DecodeString(testVectorHex)
	if len(decoded) == 0 || err != nil {
		panic("couldn't decode test vector")
	}
	return &Node{
		Key:  decoded[privKeyStart:privKeyStart+keySize],
		Code: decoded[chainCodeStart:chainCodeStart+keySize],
	}
}

func TestVectorOne(t *testing.T) {
	// Test vector 1 master node
	expected := extractNode(vectorOneMaster)
	seed, _ := hex.DecodeString(vectorOneSeed)

	actual, _ := NewMasterNode(seed)

	if !bytes.Equal(actual.Key, expected.Key) {
		t.Fatalf("Failed test vector 1. Got master key %x, expected %x", actual.Key, expected.Key)
	}

	if !bytes.Equal(actual.Code, expected.Code) {
		t.Fatalf("Failed test vector 1. Got master code %x, expected %x", actual.Code, expected.Code)
	}

	// Test vector 1 first hardened child
	expected = extractNode(vectorOneHardZero)

	_ = actual.ComputeHardenedChild(firstHardened)

	if !bytes.Equal(actual.Key, expected.Key) {
		t.Errorf("Failed test vector 1. Got first hardened child key %x, expected %x", actual.Key, expected.Key)
	}

	if !bytes.Equal(actual.Code, expected.Code) {
		t.Errorf("Failed test vector 1. Got first hardened child code %x, expected %x", actual.Code, expected.Code)
	}
}

func TestVectorTwo(t *testing.T) {
	// Test vector 2 master node
	expected := extractNode(vectorTwoMaster)
	seed, _ := hex.DecodeString(vectorTwoSeed)

	actual, _ := NewMasterNode(seed)

	if !bytes.Equal(actual.Key, expected.Key) {
		t.Fatalf("Failed test vector 2. Got master key %x, expected %x", actual.Key, expected.Key)
	}

	if !bytes.Equal(actual.Code, expected.Code) {
		t.Fatalf("Failed test vector 2. Got master code %x, expected %x", actual.Code, expected.Code)
	}
}

func TestVectorThree(t *testing.T) {
	// Test vector 3 master node
	expected := extractNode(vectorThreeMaster)
	seed, _ := hex.DecodeString(vectorThreeSeed)

	actual, _ := NewMasterNode(seed)

	if !bytes.Equal(actual.Key, expected.Key) {
		t.Fatalf("Failed test vector 3. Got master key %x, expected %x", actual.Key, expected.Key)
	}

	if !bytes.Equal(actual.Code, expected.Code) {
		t.Fatalf("Failed test vector 3. Got master code %x, expected %x", actual.Code, expected.Code)
	}

	// Test vector 3 first hardened child
	expected = extractNode(vectorThreeHardZero)

	_ = actual.ComputeHardenedChild(firstHardened)

	if !bytes.Equal(actual.Key, expected.Key) {
		t.Errorf("Failed test vector 3. Got first hardened child key %x, expected %x", actual.Key, expected.Key)
	}

	if !bytes.Equal(actual.Code, expected.Code) {
		t.Errorf("Failed test vector 3. Got first hardened child code %x, expected %x", actual.Code, expected.Code)
	}
}

// Generated test vector that has child key with leading zero byte
const (
	leadingZeroSeed = "6772b1242f27082a377b7bb2b22835efa2385eb936b37add89516a9484bca6dfcf423bd2bf53d7c259d1726684048344a70be3da87185854ca42f960d2e45ac2"
	leadingZeroIdx  = 103
	leadingZeroKey  = "005c2ee4e692e587e5ba659079f66157299d5840a0131c2b5b78a954a6bada9c"
	leadingZeroCode = "02d36d971406c51afa5357ca86dfe810e33d80b6c74dc669ad42284915037d98"
)

func TestLeadingZero(t *testing.T) {
	seed, _ := hex.DecodeString(leadingZeroSeed)
	expectedKey, _ := hex.DecodeString(leadingZeroKey)
	expectedCode, _ := hex.DecodeString(leadingZeroCode)

	actual, _ := NewMasterNode(seed)

	_ = actual.ComputeHardenedChild(leadingZeroIdx+firstHardened)

	if !bytes.Equal(actual.Key, expectedKey) {
		t.Errorf("Failed TestLeadingZero. Got %d hardened child key %x, expected %x", leadingZeroIdx, actual.Key, expectedKey)
	}

	if !bytes.Equal(actual.Code, expectedCode) {
		t.Errorf("Failed TestLeadingZero. Got %d hardened child code %x, expected %x", leadingZeroIdx, actual.Code, expectedCode)
	}
}
