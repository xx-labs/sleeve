# Sleeve audit

## Intro

This audit was performed July 16 and 17 2021 by Jean-Philippe Aumasson.

### Scope

The scope is the following:

* <https://github.com/xx-labs/sleeve/> commit fb902f659 (Jul 14, 2021)
* crypto correctness and security
* timing leaks
* unsafe API
* missing security checks
* risk from dependencies
* randomness generation

### Functionality overview

### hasher/

hasher/ implements a unified interface to SHA-2, BLAKE2, BLAKE3,
restricting the API exposure and with good test coverage.

### wots/

wots/ implements the [WOTS+](https://eprint.iacr.org/2017/965)
hash-based signature scheme, with by different parameter sets, for
example "LEVEL0":

* public keys of n=256 bits (common to all instances)
* BLAKE2b-256-based prefix PRF (common to all instances)
* SHA3-224 as message hash (common to all instances, SHA3-256 when needed)
* Winternitz parameter w=256 (common to all instances)
* seeds of n=160 bits, N=20 bytes 
* messages of m=192 bits, N=24 bytes
* ell1=192/8=24, ell2=2 ell=ell1+ell2=26 (`total` attribute)
* signature of 4424 bits = 553 bytes = 1 + 32 + ell×N

Compared to the paper, which defines a secret key as ell random numbers,
the implementation "compresses" the key and generates it from a `seed`
parameter. Likewise, the public key pk is "compressed" from a "public
seed" `pSeed`, used to generate the randomizer values, and the secret
key elements , rather than being represented as the paper suggests as a
list of elements directly (which the implementation also supports, via
the `fastSign()` function.

Furthermore, parameter definition less general than in the paper
regarding checksum encoding are explained in
<https://github.com/xx-labs/sleeve/blob/fb902f659f446dd982a53bc025b254c84a0bfe6a/wots/params.go#L29-L44>.

The Go package seems to only expose the necessary functions, hiding the
internal and low-level operations.


### wallet/

wallet/ provides HD wallet functionalities based on the BIP32/44
standard, using BIP39 mnemonics, seeing the generated private keys as
seeds (for secret keys) and chaincode as "public seeds" (those
generating the randomizers).

The path uses 1955 as coin type and hardened derivations, with paths
such as "m/44'/1955'/0'/0'/0'".

### cli-generator/

cli-generator/ provides a CLI utility to generate wallets, with an
optional passphrase, copying the address into a file address.txt.



## Security issues


### Password length not checked and password displayed

Any password length is accepted, and after being verified the CLI tool
shows the password in clear on screen.

I suggest to enforce a limit of at least 8 chars, and just check for
password equality without printing it in clear.

### Mnemonics copied on screen

It would be safer to copy the mnemonics generated into files (with 0600
permissions), rather than displaying them on-screen.
Not only it's better OPSEC-wise, but in some contexts, key ceremonies
require the operators not to see the secret values.

Furthermore, the secret files should be encrypted with a user-provided
password (maybe making this optional).


### Segfault upon invalid `NewParam()` arguments

The `n` is not checked in `NewParam()`, however it must not be bigger
than `hPrf.Size()`, because of the following in `computeSK()`:

```go
  // Hash buffer
  prfBuffer := make([]byte, 0, hPrf.Size())

  // Compute SK_i = H(SEED || i)
  for i := 0; i < k.params.total; i++ {
      prfBuffer = prf(prfBuffer, hPrf, k.seed, uint8(i))
      copy(sks[i*k.params.n:(i+1)*k.params.n], prfBuffer[0:k.params.n])
```

Because of this, `computeSK()` will segfault given a too high `n`,
because of the out-of-bound read operation.


## Misc observations

Here we list observations and suggestions not about security risks, but
potential improvements, QA, and performance.


### Verification not implemented

It seems that signature verification is not implemented, instead only
the `Decode()` (public key reconstruction).
It would be clearer to also have a function `Verify()` taking a
message, signature, and public key, and returning true or false.
If you look at the WOTS+ specs in RFC8391, verification indeed just
computes the public key, but it's because it's used as a building block
within XMSS, rather than as a signature scheme.

The closest to verification is the consistency test in
`TestKey_Sign_Consistency()`, so even if it's not defined, verification
functionality is tested.
I would recommend to add more test cases, for different instances.


### `Decode()` errors not documented

`Decode()` returns a slice and a nil one if it encounters any error,
however the caller cannot determine what error type it is.
It would be better to return a `([]byte, error)` and describe the error
encountered, it any.


### BIP44 path not injected in key generation

The diagram in wallet/docs/ shows the BIP44 path being directly injected
in the WOTS+ key gen, in addition to the BIP32 input, however the
`generateSleeve()` function only takes the BIP32 output.


### Keyed hash constructions potential optimizations

The `prf()` and `chain()` keyed hashes are constructed as
Hash(seed||index) and Hash(seed||index||maskedMsg), respectively, which
is fine here because the seed and the index are of fixed size for a
given instance.
But with variable-length values, in theory you could have collisions,
making security proofs inapplicable (and the function potential unsafe
in very weird situations).

Furthermore, hashes with built-in keyed more support like BLAKE2 and
BLAKE3, using the key parameter can save one compression computation.
Here the parameters are small enough that it does not make a difference.
But if the PRF were to be used in another contexts, it could help.

### Possibly unreliable dependencies

The project has very few dependencies (good). However:
<https://github.com/vedhavyas/go-subkey> has 4 stars and wasn't updated
in 7 months; <https://github.com/decred/base58> has 5 starts and wasn't
updated in 13 months. Neither has been audited. These both do
security-critical operations. There's a non-negligible risk that they
include bugs, or that someone introduces a malicious feature in them
(for example, under the pretext of an improvement, fooling the
maintainers).

We'd recommend to review these dependencies, or find more reliable ones
offering equivalent functionality.


### File address.txt overwritten

cli-generator will overwrite any existing address.txt, so users might
accidentally lose addresses. I'd suggest to ask for user confirmation,
or rename the file.


### CLI tool for address generation 

It might be convenient for users to provide a functionality to derive
outputs from their "root" passphrase (and optional password).



## Activity log

### 20210717

* 1h: Signature verification security testing: edge cases, abuse
  scenarios, checksum implementation; report editing.

### 20210716

* 2h: WOTS review, detailed code review, dynamic testing, observations
  writeup

* 1h: CLI review, intro update, issues and observations writeup

* 2h: WOTS+ paper refresher, code base general overview and
  understanding, Intro section writeup, dependencies review, test
  running.

