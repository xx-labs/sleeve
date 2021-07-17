package wallet

import (
	"github.com/vedhavyas/go-subkey"
	sr "github.com/vedhavyas/go-subkey/sr25519"
)

const protoNetPrefix = 42
const xxNetworkPrefix = 55

func ProtoNetAddressFromMnemonic(mnemonic string) string {
	xxWallet, err := walletFromMnemonic(mnemonic)
	if err != nil {
		return ""
	}

	addr, err := xxWallet.SS58Address(protoNetPrefix)
	if err != nil {
		return ""
	}
	return addr
}

func XXNetworkAddressFromMnemonic(mnemonic string) string {
	xxWallet, err := walletFromMnemonic(mnemonic)
	if err != nil {
		return ""
	}

	addr, err := xxWallet.SS58Address(xxNetworkPrefix)
	if err != nil {
		return ""
	}
	return addr
}

func walletFromMnemonic(mnemonic string) (subkey.KeyPair, error) {
	// Create xx sr25519 wallet
	scheme := sr.Scheme{}
	return subkey.DeriveKeyPair(scheme, mnemonic)
}
