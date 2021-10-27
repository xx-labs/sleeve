package wallet

import (
	"testing"
)

const (
	// Generated with `subkey inspect "testVectorMnemonic"`
	testVectorTestnetAddress = "5HQpup8uJbTnbNRDkiHM1t5g2aXyQuKTL2UpqBGpYZbU2Qqh"
	testVectorXXNetworkAddress = "6aeQGiB9JNqEd8gFXdievbYCRtPo8HWDnFgXq4djZgKogpRH"
	// Changed the first `T` to `t`
	invalidChecksumAddress = "5HQpup8uJbtnbNRDkiHM1t5g2aXyQuKTL2UpqBGpYZbU2Qqh"
	tooShortAddress = "5hQpup8uJbTnbNRDkiHM1t5g2aXyQu"
	tooLongAddress = "5HQpup8uJbTnbNRDkiHM1t5g2aXyQuKTL2UpqBGpYZbU2Qqhaaaaaa"
)

func TestGenerateSS58AddressConsistency(t *testing.T) {
	// Get testnet address for test vector
	testnetAddress := TestnetAddressFromMnemonic(testVectorMnemonic)

	if testnetAddress == "" {
		t.Fatalf("TestnetAddressFromMnemonic() should work for a valid mnemonic")
	}

	// Confirm address is correct
	if testnetAddress != testVectorTestnetAddress {
		t.Fatalf("Consistency violation! TestnetAddressFromMnemonic() returned wrong address. Got: %s\nExpected: %s\n",
			testnetAddress, testVectorTestnetAddress)
	}

	// Get xx network address for test vector
	xxnetAddress := XXNetworkAddressFromMnemonic(testVectorMnemonic)

	if xxnetAddress == "" {
		t.Fatalf("XXNetworkAddressFromMnemonic() should work for a valid mnemonic")
	}

	// Confirm address is correct
	if xxnetAddress != testVectorXXNetworkAddress {
		t.Fatalf("Consistency violation! XXNetworkAddressFromMnemonic() returned wrong address. Got: %s\nExpected: %s\n",
			xxnetAddress, testVectorXXNetworkAddress)
	}
}

func TestValidateSS58AddressConsistency(t *testing.T) {
	// Validate testnet test vector address
	valid, err := ValidateTestnetAddress(testVectorTestnetAddress)

	if err != nil {
		t.Fatalf("ValidateTestnetAddress() should work for valid testnet address. Got error %s instead", err)
	}

	if !valid {
		t.Fatalf("Consistency violation! ValidateTestnetAddress() should return true for valid testnet address")
	}

	// Validate testnet vector address for xx network (should fail)
	_, err = ValidateXXNetworkAddress(testVectorTestnetAddress)

	if err == nil {
		t.Fatalf("ValidateXXNetworkAddress() should fail for invalid xx network address")
	}

	// Validate xx network test vector address
	valid, err = ValidateXXNetworkAddress(testVectorXXNetworkAddress)

	if err != nil {
		t.Fatalf("ValidateXXNetworkAddress() should work for valid xx network address. Got error %s instead", err)
	}

	if !valid {
		t.Fatalf("Consistency violation! ValidateXXNetworkAddress() should return true for valid xx network address")
	}

	// Validate xx network vector address for testnet (should fail)
	_, err = ValidateTestnetAddress(testVectorXXNetworkAddress)

	if err == nil {
		t.Fatalf("ValidateTestnetAddress() should fail for invalid testnet address")
	}
}

func TestAddressFromInvalidMnemonic(t *testing.T) {
	// Test invalid mnemonic
	randMnem := "one two three xx    network   sleeve implementation"

	addr := TestnetAddressFromMnemonic(randMnem)

	if addr != "" {
		t.Fatalf("TestnetAddressFromMnemonic() should fail for invalid mnemonic")
	}

	addr = XXNetworkAddressFromMnemonic(randMnem)

	if addr != "" {
		t.Fatalf("XXNetworkAddressFromMnemonic() should fail for invalid mnemonic")
	}
}

func TestValidateSS58Address(t *testing.T) {
	// Test invalid address lengths
	valid, err := validateSS58Address(testnetPrefix, tooShortAddress)

	if valid || err == nil {
		t.Fatalf("validateSS58Address() should fail for invalid lenght address")
	}

	valid, err = validateSS58Address(testnetPrefix, tooLongAddress)

	if valid || err == nil {
		t.Fatalf("validateSS58Address() should fail for invalid lenght address")
	}

	// Test invalid checksum
	valid, err = validateSS58Address(testnetPrefix, invalidChecksumAddress)

	if valid || err == nil {
		t.Fatalf("validateSS58Address() should fail for invalid checksum address")
	}
}
