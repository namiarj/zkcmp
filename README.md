# zkcmp

**Zero-knowledge file possession and comparison utility.**

`zkcmp` is a minimal Unix utility exploring whether knowledge of a file-derived or password-derived secret can be demonstrated without revealing the secret itself.

## Status

> **Experimental / exploratory software.**
>
> The protocol and implementation are still evolving. Do not rely on `zkcmp` for security-critical applications, authentication, or protection of valuable secrets.

## How it works

`zkcmp` derives a secret from a file, or from a password:

```text
file or password
↓
hash
↓
commitment
↓
zero-knowledge proof
```

The proof is constructed so that the secret itself does not need to be transmitted.

The current implementation uses a Schnorr-style proof of knowledge over a 3072-bit MODP group.

The default hash is SHA-256. SHA3-256 or SHA512-256 can also be selected.

[Read more about Schnorr proof.](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/)

## Commands

```
zkcmp [-h sha256|sha3-256|sha512-256] [-s psk] -c file -o commit
zkcmp [-h sha256|sha3-256|sha512-256] [-s psk] -p file -o proof
zkcmp [-h sha256|sha3-256|sha512-256] [-s psk] -C -o commit
zkcmp [-h sha256|sha3-256|sha512-256] [-s psk] -P -o proof
zkcmp -g psk
zkcmp [-q] [-h sha256|sha3-256|sha512-256] commit proof
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

Exit status is `0` on a match and `1` on a mismatch. `-q` suppresses the mismatch message.

This is useful when a commitment has been published and multiple parties need to demonstrate knowledge of the corresponding secret.

For example:

```sh
server$ zkcmp -c release.tar -o release.tar.commit

alice$ zkcmp -p release.tar -o alice.proof
bob$   zkcmp -p release.tar -o bob.proof

server$ zkcmp release.tar.commit alice.proof
server$ zkcmp release.tar.commit bob.proof
```

## Pre-shared key

A commitment is a deterministic function of the file. Anyone who can guess or obtain the file can compute the same commitment and check their guess against it.

To prevent this, mix in a pre-shared key (psk) with `-s`. The same psk must be used when committing and proving.

### `-g`

Generates a random psk and writes it to a new file with mode `0600`. Existing files are never overwritten.

```sh
zkcmp -g shared.psk
zkcmp -s shared.psk -c release.tar -o release.tar.commit
zkcmp -s shared.psk -p release.tar -o alice.proof
```

Verification does not need the psk.

## Password mode

`-C` and `-P` work like `-c` and `-p`, but the secret is a password typed at the terminal instead of a file. The password is proven without ever being sent to the verifier.

```sh
zkcmp -g user.psk                        # one salt per user
zkcmp -s user.psk -C -o user.commit      # register (asks twice)
zkcmp -s user.psk -P -o user.proof       # authenticate (asks once)
zkcmp user.commit user.proof             # verify
```

## Building

On FreeBSD & OpenBSD:

```sh
make
make install
```

On OpenBSD, `zkcmp` uses `pledge(2)` and drops all file access after reading its inputs.

## License

See [`LICENSE`](LICENSE) for licensing information.

## Author

Nami Arjmandi
