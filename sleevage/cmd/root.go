////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2021 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"strings"
)

// Input related flags
var quantumPhrase string
var passphrase string
var account uint32
var wotsSecurityLevel string
var numWallets uint32
var numAccounts uint32
var prefix string
var derivations uint32

// Input files flags
var quantumPhraseFile string
var passphraseFile string

// Output related flags
var outputFile string
var outputType string
var testnet bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sleevage",
	Short: "sleevage is a tool to generate xx network Sleeve wallets",
	Long: `Sleeve is a novel way of embedding a quantum secure key in the
generation of curve based, non quantum secure keys
Find out more about Sleeve at: xx.network/sleeve

When no arguments are provided, sleevage generates a new Sleeve wallet from scratch.
If a quantum recovery phrase is provided, sleevage will recover the embedded
standard recovery phrase and respective address.

`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if !checkArgs() {
			return
		}
		sl, err := sleeve()
		if err != nil {
			fmt.Printf("Error generating Sleeve wallet: %s\n", err.Error())
			return
		}
		handleOutput(sl)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	// Get arguments from files if needed
	cobra.OnInitialize(readInputFiles)

	// Input flags
	rootCmd.PersistentFlags().StringVarP(&quantumPhrase, "quantum", "q", "", "specify the quantum recovery phrase. Leave empty to generate a new Sleeve from scratch")
	rootCmd.PersistentFlags().StringVarP(&passphrase, "pass", "p", "", "specify a passphrase")
	rootCmd.PersistentFlags().Uint32VarP(&account, "account", "a", 0, "specify the account number")
	rootCmd.PersistentFlags().StringVarP(&wotsSecurityLevel, "security", "s", "level0", "specify the WOTS+ security level. One of [level0, level1, level2, level3]")
	rootCmd.PersistentFlags().Uint32VarP(&numWallets, "wallets", "w", 1, "specify the number of Sleeve wallets to generate")
	rootCmd.PersistentFlags().Uint32VarP(&numAccounts, "num-accounts", "n", 1, "specify the number of accounts to derive for each wallet")
	rootCmd.PersistentFlags().StringVarP(&prefix, "prefix", "x", "", "derivation path prefix for standard wallet")
	rootCmd.PersistentFlags().Uint32VarP(&derivations, "derive", "d", 0, "number of accounts to derive from standard wallet. Appended to the prefix")

	// Input from file
	rootCmd.PersistentFlags().StringVar(&quantumPhraseFile, "quantum-file", "", "specify the quantum recovery phrase from a file. Overwrites the value of --quantum")
	rootCmd.PersistentFlags().StringVar(&passphraseFile, "pass-file", "", "specify a passphrase from a file. Overwrites the value of --pass")

	// Output flags
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output","o", "", "output file. Defaults to stdout. When specified, only address is shown on stdout")
	rootCmd.PersistentFlags().StringVarP(&outputType, "output-type","t", "text", "output type. One of [text, json]")
	rootCmd.PersistentFlags().BoolVar(&testnet, "testnet",  false, "generate testnet address")
}

func checkArgs() bool {
	// Can't recover multiple wallets
	if quantumPhrase != "" && numWallets != 1 {
		fmt.Println("Can't use a given quantum recovery phrase with more than 1 wallet")
		return false
	}
	// Check output type
	switch  outputType {
	case "text":
		// noop
	case "json":
		// noop
	default:
		fmt.Println("Invalid output type")
		return false
	}
	return true
}

func readInputFiles() {
	// Read quantum recovery phrase from file if specified
	if quantumPhraseFile != "" {
		val, err := ioutil.ReadFile(quantumPhraseFile)

		if err != nil {
			panic(fmt.Sprintf("error opening quantum phrase file: %s", err))
		}
		quantumPhrase = string(val)
		quantumPhrase = strings.TrimRight(quantumPhrase, "\r\n")
	}

	// Read passphrase from file if specified
	if passphraseFile != "" {
		val, err := ioutil.ReadFile(passphraseFile)

		if err != nil {
			panic(fmt.Sprintf("error opening passphrase file: %s", err))
		}
		passphrase = string(val)
		passphrase = strings.TrimRight(passphrase, "\r\n")
	}
}

func handleOutput(sl []SleeveJson) {
	// Get output according to type
	var out []byte
	var err error
	switch  outputType {
	case "text":
		for _, s := range sl {
			out = append(out, fmt.Sprintf("%s\n\n", s.String())...)
		}
	case "json":
		// noop
		out, err = json.MarshalIndent(sl, "", "  ")
		if err != nil {
			panic(fmt.Sprintf("error marshalling sleeve data to json: %s", err))
		}
	default:
		// noop
	}
	// If an output file was specified, write output to file
	if outputFile != "" {
		err = ioutil.WriteFile(outputFile, out, 400)
		if err != nil {
			panic(fmt.Sprintf("error writing sleeve data to file: %s", err))
		}
		// Write just addresses to stdout
		for _, s := range sl {
			fmt.Println(s.Address)
			for _, deriv := range s.StandardDeriv {
				fmt.Println(deriv.Address)
			}
		}
	} else {
		// Write to stdout
		fmt.Println(string(out))
	}
}
