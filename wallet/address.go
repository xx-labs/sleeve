package wallet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/vedhavyas/go-subkey"
	sr "github.com/vedhavyas/go-subkey/sr25519"
	"github.com/xx-labs/sleeve/hasher"
	"sort"
)

const testnetPrefix = 42
const xxNetworkPrefix = 55

//////////////////////////////////////////////////
//-------------- SR25519 ACCOUNTS --------------//
//////////////////////////////////////////////////

func TestnetAddressFromMnemonic(mnemonic string) string {
	xxWallet, err := sr25519WalletFromMnemonic(mnemonic)
	if err != nil {
		return ""
	}
	return generateSS58Address(testnetPrefix, xxWallet.Public())
}

func ValidateTestnetAddress(address string) (bool, error) {
	return validateSS58Address(testnetPrefix, address)
}

func XXNetworkAddressFromMnemonic(mnemonic string) string {
	xxWallet, err := sr25519WalletFromMnemonic(mnemonic)
	if err != nil {
		return ""
	}
	return generateSS58Address(xxNetworkPrefix, xxWallet.Public())
}

func ValidateXXNetworkAddress(address string) (bool, error) {
	return validateSS58Address(xxNetworkPrefix, address)
}

// Substrate standard sr25519 wallet
func sr25519WalletFromMnemonic(mnemonic string) (subkey.KeyPair, error) {
	// Create xx sr25519 wallet
	scheme := sr.Scheme{}
	return subkey.DeriveKeyPair(scheme, mnemonic)

}

//////////////////////////////////////////////////
//------------- MULTISIG ACCOUNTS --------------//
//////////////////////////////////////////////////

// Maximum of 63 signatories (max length of parity scale compact encoding of an integer that fits in 1 byte)
const maxSignatories = 63

// Derive a Multisig address from signatories addresses and threshold
// MSigAddress = BLAKE2B_256("modlpy/utilisuba" || signatories.length << 2 || sorted_signatories || threshold)
func DeriveMultisigAddress(signatories []string, threshold uint16) (string, error) {
	// 1. Basic checks
	size := len(signatories)
	// 1.1. Check at least one signatory
	if size == 0 {
		return "", errors.New("signatories can't be empty")
	}
	// 1.2. Check not too many signatories
	if size > maxSignatories {
		return "", errors.New(
			fmt.Sprintf("too many signatories: got %d, max %d", size, maxSignatories))
	}
	// 1.3. Check threshold isn't zero
	if int(threshold) == 0 {
		return "", errors.New("threshold can't be zero")
	}
	// 1.4. Check threshold is smaller or equal to signatories size
	if size < int(threshold) {
		return "", errors.New(
			fmt.Sprintf("invalid threshold: got %d, with %d signatories", threshold, size))
	}

	// 2. Get network id from first signatory and check all are using the same
	var network uint8
	var err error
	network, err = extractNetworkId(signatories[0])
	if err != nil {
		return "", err
	}

	// 3. Validate signatories addresses
	for _, sig := range signatories {
		_, err = validateSS58Address(network, sig)
		if err != nil {
			return "", err
		}
	}

	// 4. Convert signatories addresses to public keys
	keys := make([][]byte, size)
	for i, sig := range signatories {
		keys[i] = extractPublicKey(sig)
	}

	// 5. Sort public keys
	sort.Slice(keys, func(i int, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })

	// 6. Derive multisig address
	h := hasher.BLAKE2B_256.New()
	str := "modlpy/utilisuba"
	h.Write([]byte(str))
	length := uint8(size << 2)
	h.Write([]byte{length})
	for _, key := range keys {
		h.Write(key)
	}
	tBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(tBytes, threshold)
	h.Write(tBytes)
	res := h.Sum(nil)
	return generateSS58Address(network, res), nil
}

//////////////////////////////////////////////////
//---------------- SS58 ADDRESS ----------------//
//////////////////////////////////////////////////

// SS58 format: networkID (1 byte) || pubkey (32 bytes) || checksum (2 bytes)
// checksum = BLAKE2B_512("SS58PRE" || networkID || pubkey)[0:2]
const (
	networkIDLen = 1
	pubKeyLen = 32
	checksumLen = 2
	addressLen = networkIDLen + pubKeyLen + checksumLen
	networkIDPos = 0
	checksumPos = 33
	ss58Prefix = "SS58PRE"
)

// SS58 address generation
func generateSS58Address(network uint8, pubkey []byte) string {
	// 1. Compute checksum
	h := hasher.BLAKE2B_512.New()
	h.Write([]byte(ss58Prefix))
	h.Write([]byte{network})
	h.Write(pubkey)
	checksum := h.Sum(nil)[:checksumLen]

	// 2. Create address data
	data := append([]byte{network}, pubkey...)
	data = append(data, checksum...)

	// 3. Base58 encode
	return base58.Encode(data)
}

// SS58 address validation
func validateSS58Address(network uint8, address string) (bool, error) {
	// 1. Base58 decode string
	data := base58.Decode(address)

	// 2. Check address length
	if len(data) != addressLen {
		return false, errors.New(
			fmt.Sprintf("incorrect address length: got %d, expected %d", len(data), addressLen))
	}
	netID := data[networkIDPos]
	checksumData := data[:checksumPos]
	checksum := data[checksumPos:]

	// 3. Verify networkID (1st byte)
	if netID != network {
		return false, errors.New(
			fmt.Sprintf("incorrect networkID: got %d, expected %d", netID, network))
	}

	// 4. Compute and verify checksum
	h := hasher.BLAKE2B_512.New()
	h.Write([]byte(ss58Prefix))
	h.Write(checksumData)
	computedChecksum := h.Sum(nil)[:checksumLen]
	if !bytes.Equal(computedChecksum, checksum) {
		return false, errors.New(
			fmt.Sprintf("incorrect checksum: got %x, expected %x", computedChecksum, checksum))
	}

	return true, nil
}

// extract network id from address
func extractNetworkId(address string) (byte, error) {
	// 1. Base58 decode string
	data := base58.Decode(address)

	// 2. Check address length
	if len(data) != addressLen {
		return 0x00, errors.New(
			fmt.Sprintf("incorrect address length: got %d, expected %d", len(data), addressLen))
	}
	return data[networkIDPos], nil
}

// extract public key from valid address
func extractPublicKey(address string) []byte {
	data := base58.Decode(address)
	return data[networkIDLen:checksumPos]
}
