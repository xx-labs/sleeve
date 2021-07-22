package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"github.com/fatih/color"
	"github.com/xx-labs/sleeve/wallet"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type SleeveJson struct {
	Sleeve     string  `json:"Sleeve"`
	Address    string  `json:"Address"`
	Mnemonic   string  `json:"Mnemonic"`
}

func GenerateWallet() (SleeveJson, error) {
	// 1. Generate sleeve wallet
	sleeve, err := wallet.NewSleeve(rand.Reader, "")
	if err != nil {
		return SleeveJson{}, err
	}

	// 2. Get ProtoNet Address
	addr := wallet.ProtoNetAddressFromMnemonic(sleeve.GetOutputMnemonic())
	if addr == "" {
		return SleeveJson{}, nil
	}

	// 3. return wallet JSON
	return SleeveJson{
		Sleeve:    sleeve.GetMnemonic(),
		Address:   addr,
		Mnemonic:  sleeve.GetOutputMnemonic(),
	}, nil
}

func Clear() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

func WaitForEnter() {
	buf := bufio.NewReader(os.Stdin)
	fmt.Println()
	fmt.Println("   Press enter to continue")
	_, _ = buf.ReadBytes('\n')
	Clear()
	fmt.Println()
	fmt.Println()
}

func WaitForEnterNoClear() {
	buf := bufio.NewReader(os.Stdin)
	fmt.Println()
	fmt.Println("   Press enter to continue")
	_, _ = buf.ReadBytes('\n')
	fmt.Println()
	fmt.Println()
}

func MnemPrint(mnemonic string) {
	// Print 24 words split into 4 sets of 6
	words := strings.Split(mnemonic, " ")
	for i := 0; i < 4; i++ {
		fmt.Println("   " + strings.Join(words[6*i:6*(i+1)], " "))
	}
}

func main() {
	Clear()
	xxnet := color.CyanString("xx network")
	fmt.Println()
	fmt.Println()
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  Welcome to the " + xxnet + " Sleeve wallet generation tool!  |")
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	fmt.Println()
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  Sleeve is a novel way of embedding a quantum secure key   |")
	fmt.Println("|  in the generation of curve based, non quantum secure keys |")
	fmt.Println("|                                                            |")
	fmt.Println("|  Find out more about Sleeve at: github.com/xx-labs/sleeve  |")
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	fmt.Println()
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  This tool will generate three outputs that MUST be stored |")
	str := color.CyanString("1. the Sleeve wallet mnemonic phrase")
	fmt.Println("|    " + str + "                    |")
	str = color.GreenString("2. the regular wallet mnemonic phrase")
	fmt.Println("|    " + str + "                   |")
	str = color.MagentaString("3. the regular wallet address")
	fmt.Println("|    " + str + "                           |")
	color.Unset()
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	WaitForEnter()

	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  Step 1.             Sleeve wallet generation              |")
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	fmt.Println()
	color.Set(color.FgRed)
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  WARNING: You MUST securely store the Sleeve mnemonic for  |")
	fmt.Println("|  future use of the quantum secure wallet in xx network!!!  |")
	fmt.Println("|------------------------------------------------------------|")
	color.Unset()
	fmt.Println()
	WaitForEnterNoClear()

	sleeve, err := GenerateWallet()
	if err != nil {
		panic("Error generating Sleeve wallet: " + err.Error())
	}

	fmt.Println()
	fmt.Println("   This is your Sleeve wallet mnemonic phrase:")
	fmt.Println()
	color.Set(color.FgCyan)
	MnemPrint(sleeve.Sleeve)
	color.Unset()
	fmt.Println()
	fmt.Println()
	color.Set(color.FgRed)
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  WARNING: Before proceeding, get a paper and pen, write    |")
	fmt.Println("|  down the mnemonic phrase, and store it in a safe place!   |")
	fmt.Println("|------------------------------------------------------------|")
	color.Unset()
	fmt.Println()
	WaitForEnter()

	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  Step 2.       Non quantum secure wallet generation        |")
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	fmt.Println()
	fmt.Println("   This is your non quantum secure wallet mnemonic phrase:")
	fmt.Println()
	color.Set(color.FgGreen)
	MnemPrint(sleeve.Mnemonic)
	color.Unset()
	fmt.Println()
	fmt.Println()
	color.Set(color.FgRed)
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  WARNING: Before proceeding, get a paper and pen, write    |")
	fmt.Println("|  down the mnemonic phrase, and store it in a safe place!   |")
	fmt.Println("|------------------------------------------------------------|")
	color.Unset()
	fmt.Println()
	WaitForEnter()

	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  Step 3.           " + xxnet + " wallet address               |")
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	fmt.Println()
	color.Set(color.FgYellow)
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  NOTE: This address is the default one derived from the    |")
	fmt.Println("|  mnemonic shown before. If you choose to use the mnemonic  |")
	fmt.Println("|  in a Ledger device, or in any wallet application, please  |")
	fmt.Println("|  be aware that different addresses might be generated      |")
	fmt.Println("|------------------------------------------------------------|")
	color.Unset()
	fmt.Println()
	fmt.Println()
	fmt.Println("   This is your wallet address:")
	fmt.Println()
	color.Set(color.FgMagenta)
	fmt.Printf("   " + sleeve.Address)
	color.Unset()
	fmt.Println()
	fmt.Println()
	fmt.Println("   Before proceeding, write down or copy the address. You can ")
	fmt.Println("   also find it in 'address.txt' after exiting this tool      ")

	file, err := os.Create("address.txt")
	if err != nil {
		panic("Error creating address.txt file: " + err.Error())
	}
	_, _ = file.WriteString(sleeve.Address + "\n")
	_ = file.Close()

	fmt.Println()
	WaitForEnter()

	fmt.Println("|------------------------------------------------------------|")
	fmt.Println("|  Wallet generation is complete! For security purposes      |")
	fmt.Println("|  please make sure to close your terminal after exiting     |")
	fmt.Println("|------------------------------------------------------------|")
	fmt.Println()
	WaitForEnter()
}
