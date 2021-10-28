////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2021 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/xx-labs/sleeve/hasher"
	"github.com/xx-labs/sleeve/wallet"
	"github.com/xx-labs/sleeve/wots"
	"strings"
)

type SleeveJson struct {
	Quantum  string `json:"QuantumPhrase"`
	Pass     string `json:"Passphrase"`
	Path     string `json:"DerivationPath"`
	Standard string `json:"StandardPhrase"`
	Address  string `json:"Address"`
}

func (s SleeveJson) String() string {
	str := fmt.Sprintf("quantum recovery phrase: %s\n", s.Quantum)
	str += fmt.Sprintf("passphrase: %s\n", s.Pass)
	str += fmt.Sprintf("path: %s\n", s.Path)
	str += fmt.Sprintf("standard recovery phrase: %s\n", s.Standard)
	str += fmt.Sprintf("address: %s", s.Address)
	return str
}

type args struct {
	generate bool
	quantum  string
	pass     string
	spec     wallet.GenSpec
	path     string
}

func parseArgs() (args, error) {
	// If quantum phrase is not empty, then don't generate new wallet
	generate := true
	if quantumPhrase != "" {
		generate = false
	}

	// Select wots+ security level
	level := wots.DefaultParams
	switch wotsSecurityLevel {
	case "level0":
		level = wots.Level0
	case "level1":
		level = wots.Level1
	case "level2":
		level = wots.Level2
	case "level3":
		level = wots.Level3
	default:
		return args{}, errors.New(fmt.Sprintf("invalid WOTS+ security level specified: %s", wotsSecurityLevel))
	}

	spec := wallet.NewGenSpec(account, level)
	// Validate path from spec
	path, err := spec.PathFromSpec()
	if err != nil {
		return args{}, errors.New(fmt.Sprintf("error creating derivation path: %s. Account number is too large", err))
	}

	return args{
		generate: generate,
		quantum: quantumPhrase,
		pass: passphrase,
		spec: spec,
		path: path.String(),
	}, nil
}

func getSleeve(args args) (SleeveJson, error) {
	var err error
	var sleeve *wallet.Sleeve
	if args.generate {
		sleeve, err = wallet.NewSleeve(rand.Reader, args.pass, args.spec)
		if err != nil {
			return SleeveJson{}, err
		}
	} else {
		sleeve, err = wallet.NewSleeveFromMnemonic(args.quantum, args.pass, args.spec)
		if err != nil {
			return SleeveJson{}, err
		}
	}
	json := getJson(args.path, sleeve)
	return json, nil
}

func getAddress(sleeve *wallet.Sleeve) string {
	if testnet {
		return wallet.TestnetAddressFromMnemonic(sleeve.GetOutputMnemonic())
	}
	return wallet.XXNetworkAddressFromMnemonic(sleeve.GetOutputMnemonic())
}

func getJson(path string, sleeve *wallet.Sleeve) SleeveJson {
	return SleeveJson{
		Quantum:  sleeve.GetMnemonic(),
		Pass:     passphrase,
		Path:     path,
		Standard: sleeve.GetOutputMnemonic(),
		Address:  getAddress(sleeve),
	}
}

func sleeve() (SleeveJson, error) {
	// Parse args
	args, err := parseArgs()
	if err != nil {
		return SleeveJson{}, err
	}

	// Vanity generator
	if vanity != "" {
		return vanityGen(args)
	}

	// Regular generation
	return getSleeve(args)
}

func vanityGen(args args) (SleeveJson, error) {
	tries := uint32(0)
	entropy := make([]byte, wallet.EntropySize)
	n, err := rand.Read(entropy)
	if err != nil {
		return SleeveJson{}, err
	}
	if n != wallet.EntropySize {
		return SleeveJson{}, errors.New("couldn't read 32 bytes of entropy")
	}
	h := hasher.BLAKE2B_256.New()
	for {
		sleeve, err := wallet.NewSleeveFromEntropy(entropy, args.pass, args.spec)
		if err != nil {
			return SleeveJson{}, err
		}
		json := getJson(args.path, sleeve)
		if addressHasVanity(json.Address) {
			return json, nil
		}
		h.Write(entropy)
		entropy = h.Sum(nil)
		tries++
		// Uint32 wrapped around
		if tries == 0 {
			return SleeveJson{}, errors.New("couldn't generate vanity address after trying 2^32 seeds")
		}
	}
}

func addressHasVanity(address string) bool {
	// Convert address to lower case
	lowerAddress := strings.ToLower(address)
	// Convert vanity to lower case
	lowerVanity := strings.ToLower(vanity)
	idx := strings.Index(lowerAddress, lowerVanity)
	return idx == 1
}
