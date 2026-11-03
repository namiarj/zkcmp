# zkcmp

**Zero-knowledge file possession and comparison utility.**

`zkcmp` is a minimal Unix utility exploring whether knowledge of a file-derived or password-derived secret can be demonstrated without revealing the secret itself.

## How it works

`zkcmp` derives a secret from a file, or from a password:

```text
file or password (mixed with optional salt)
↓
hash
↓
commitment
↓
zero-knowledge proof
```

The proof is constructed so that the secret itself does not need to be transmitted.

The current implementation uses a Schnorr-style proof of knowledge over the 3072-bit MODP group from RFC 3526. The proof is non-interactive, using the Fiat-Shamir transform.

The default hash is SHA-256. SHA3-256 or SHA512-256 can also be selected.

[Read more about Schnorr proofs.](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/)

## Commands

```
zkcmp [-h sha256|sha3-256|sha512-256] [-s salt] -c file -o commit
zkcmp [-h sha256|sha3-256|sha512-256] [-s salt] -p file [-t seconds] -o proof
zkcmp [-h sha256|sha3-256|sha512-256] [-s salt] -C -o commit
zkcmp [-h sha256|sha3-256|sha512-256] [-s salt] -P [-t seconds] -o proof
zkcmp -g salt
zkcmp [-q] [-h sha256|sha3-256|sha512-256] [-t seconds] commit proof
```

### `-c`

Creates a reusable public commitment from a file.

```sh
zkcmp -c release.tar -o release.tar.commit
```

A commitment can be published once and used as the public statement for multiple independent proofs.

### `-p`

Creates a proof from a local file.

```sh
zkcmp -p release.tar -o release.tar.proof
```

### Verification

Verifies a proof against a previously created commitment.

```sh
zkcmp release.tar.commit release.tar.proof
```

Exit status is `0` on a match, `1` on a mismatch or expired proof, and `2` on error. `-q` suppresses the failure message.

This is useful when a commitment has been published and multiple parties need to demonstrate knowledge of the corresponding secret.

For example:

```sh
server$ zkcmp -c release.tar -o release.tar.commit

alice$ zkcmp -p release.tar -o alice.proof
bob$   zkcmp -p release.tar -o bob.proof

server$ zkcmp release.tar.commit alice.proof
server$ zkcmp release.tar.commit bob.proof
```

### `-t`

Binds a proof to a time window. The clock is divided into windows of `seconds` length, and the index of the window the proof was created in is hashed into the challenge.

```sh
zkcmp -p release.tar -t 3600 -o release.tar.proof    # prover
zkcmp -t 3600 release.tar.commit release.tar.proof   # verifier
```

A proof is valid for at least `seconds` and at most twice that. The verifier must pass the same `-t` value the prover used. A bounded proof does not verify without `-t`, and an unbounded proof does not verify with it.

`-t` is only valid with `-p`, `-P`, and verification.

## Private Salt

A commitment is a deterministic function of the file. Anyone who can guess or obtain the file can compute the same commitment and check their guess against it.

To prevent this, mix in a private salt with `-s`. The same private salt must be used when committing and proving.

### `-g`

Generates a random 32 byte salt and writes it to a file. The file is created with mode `0600`.

```sh
zkcmp -g shared.salt
zkcmp -s shared.salt -c release.tar -o release.tar.commit
zkcmp -s shared.salt -p release.tar -o alice.proof
```

Verification does not need the salt.

## Password mode

`-C` and `-P` work like `-c` and `-p`, but the secret is a password typed at the terminal instead of a file. The password is proven without ever being sent to the verifier.

```sh
zkcmp -g user.salt                        # one salt per user
zkcmp -s user.salt -C -o user.commit      # register (asks twice)
zkcmp -s user.salt -P -o user.proof       # authenticate (asks once)
zkcmp user.commit user.proof              # verify
```

## Building

On FreeBSD, OpenBSD, and Linux:

```sh
make
make install
```

On OpenBSD, `zkcmp` uses `pledge(2)` and drops all file access after reading its inputs.

## License

See [`LICENSE`](LICENSE) for licensing information.

## Author

Nami Arjmandi
