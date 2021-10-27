package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/vedhavyas/go-subkey"
	sr "github.com/vedhavyas/go-subkey/sr25519"
	"github.com/xx-labs/sleeve/hasher"
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
