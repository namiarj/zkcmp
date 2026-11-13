# zkcmp

Zero-knowledge comparison of files and passwords. Prove that you hold the same secret as a published commitment, without revealing the secret.

```sh
zkcmp -c release.tar release.tar.commit    # publish a commitment
zkcmp -p release.tar release.tar.proof     # prove you hold the file
zkcmp release.tar.commit release.tar.proof # verify
```

## How it works

```text
file or password
↓ hash (SHA-256, SHA3-256, or SHA512-256)
↓ PBKDF2-HMAC-SHA512, salted with the optional secret salt
↓ commitment
↓ Schnorr proof of knowledge (Fiat-Shamir, RFC 3526 3072-bit group)
```

The commitment is a deterministic function of the secret and the salt. Without a salt, anyone who can guess the file or password can recompute the commitment and check the guess. A private salt (`-s`) prevents this, because the attacker must also know the salt. Proofs use fresh randomness, so two proofs from the same secret differ and do not reveal the secret. [Read more about Schnorr proofs.](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/)

- **Non-interactive:** the prover writes one proof file. No round trip.
- **Reusable commitments:** publish one commitment, then many provers can prove against it.
- **Time-bound:** `-t` limits how long a proof stays valid.
- **Password mode:** `-C` and `-P` read a password from the terminal instead of a file.

## Usage

```text
zkcmp -c [-h hash] [-s salt] file commit
zkcmp -p [-h hash] [-s salt] [-t seconds] file proof
zkcmp -C [-h hash] [-s salt] commit
zkcmp -P [-h hash] [-s salt] [-t seconds] proof
zkcmp -g salt
zkcmp [-q] [-h hash] [-t seconds] commit proof
```

- `-c` / `-C` create a commitment from a file / password.
- `-p` / `-P` create a proof from a file / password.
- `-g` generates a random 32-byte salt file, mode `0600`.
- `-h` selects the hash: `sha256` (default), `sha3-256`, or `sha512-256`.
- `-s` names the secret salt file, used on commit and prove.
- `-t` sets the time window in seconds, for prove and verify only.
- `-q` suppresses the mismatch message on verify.

Exit status is `0` on match, `1` on mismatch or expired proof, and `2` on error.

## Multiple provers

```sh
server$ zkcmp -c release.tar release.tar.commit
alice$  zkcmp -p release.tar alice.proof
bob$    zkcmp -p release.tar bob.proof
server$ zkcmp release.tar.commit alice.proof
server$ zkcmp release.tar.commit bob.proof
```

Without `-s`, the commitment depends only on the file. Anyone who has the file can prove against it, so keep the file private if that matters.

## Time-bound proofs

```sh
zkcmp -p -t 3600 release.tar release.tar.proof     # prover
zkcmp -t 3600 release.tar.commit release.tar.proof # verifier
```

The clock is divided into windows of `seconds` length, and the proof is bound to the window it was created in. A proof stays valid for at least `seconds` and at most twice that. The verifier must pass the same `-t` the prover used.

## Salts and passwords

```sh
zkcmp -g user.salt                # create one salt per user
zkcmp -s user.salt -C user.commit # register (asks twice)
zkcmp -s user.salt -P user.proof  # authenticate (asks once)
zkcmp user.commit user.proof      # verify
```

Salt files must be exactly 32 bytes. Verification does not read the salt, so the verifier never needs it. Keep the salt secret from anyone who should not be able to check guesses against the commitment, including the verifier. If several provers share one salt, they must all receive it from a trusted channel.

## Building

Requires OpenSSL (`libcrypto`). On Linux, also requires `libbsd`.

```sh
make
make install
```

## License

See [`LICENSE`](LICENSE).

## Author

Nami Arjmandi
