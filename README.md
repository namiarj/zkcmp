# zkcmp

Prove that you hold the same file or password as a published commitment, without revealing it.

```sh
zkcmp -c release.tar release.tar.commit    # publish a commitment
zkcmp -p release.tar release.tar.proof     # prove you hold the file
zkcmp release.tar.commit release.tar.proof # verify
```

## How it works

The file (or password) is hashed, then stretched with PBKDF2-HMAC-SHA512. The result is the secret `x`, and the commitment is `g^x mod p` in the 3072-bit RFC 3526 group.

A proof is a non-interactive Schnorr proof of knowledge of `x` (Fiat-Shamir). It is fresh on every run, and the verifier learns only whether it is valid.

Commitments are deterministic. Anyone who can guess the secret can recompute the commitment and check the guess, so use a salt (`-s`) for low-entropy secrets.

## Usage

```text
zkcmp -c [-h hash] [-s salt] file commit
zkcmp -p [-h hash] [-s salt] [-t seconds] [-x context] file proof
zkcmp -C [-h hash] [-s salt] commit
zkcmp -P [-h hash] [-s salt] [-t seconds] [-x context] proof
zkcmp -g salt
zkcmp [-q] [-h hash] [-t seconds] [-x context] commit proof
```

- `-c`, `-p`: commit or prove a file.
- `-C`, `-P`: commit or prove a password, typed at the terminal.
- `-g`: write a random 32-byte salt file, mode 0600.
- `-h`: hash function, `sha256` (default), `sha3-256`, or `sha512-256`.
- `-s`: salt file. Must be exactly 32 bytes. Needed to commit and prove, not to verify.
- `-t`: time window in seconds. Used when proving and verifying.
- `-x`: context string. Used when proving and verifying.
- `-q`: no message on mismatch.

Verification exits `0` if the proof matches, `1` on mismatch or expired proof, and `2` on error.

## Context binding

`-x` ties a proof to one verifier. The verifier must pass the same string:

```sh
zkcmp -x app-a -p release.tar alice.proof         # prover
zkcmp -x app-a release.tar.commit alice.proof     # accepted
zkcmp -x app-b release.tar.commit alice.proof     # rejected
```

## Time-bound proofs

```sh
zkcmp -p -t 3600 release.tar release.tar.proof     # prover
zkcmp -t 3600 release.tar.commit release.tar.proof # verifier
```

The clock is split into windows of `seconds`. A proof is accepted for at least `seconds` and at most twice that. Both sides must pass the same `-t`.

## Streaming a proof

Use `-` as the proof name to write it to standard output:

```sh
zkcmp -p release.tar - | curl -sT - https://verifier.example/submit
```

## Multiple provers

Publish one commitment, and let each prover make their own proof:

```sh
server$ zkcmp -c release.tar release.tar.commit
alice$  zkcmp -p release.tar alice.proof
bob$    zkcmp -p release.tar bob.proof
server$ zkcmp release.tar.commit alice.proof
server$ zkcmp release.tar.commit bob.proof
```

## Passwords

```sh
zkcmp -g user.salt                # once per user
zkcmp -s user.salt -C user.commit # register (asks twice)
zkcmp -s user.salt -P user.proof  # authenticate (asks once)
zkcmp user.commit user.proof      # verify
```

Verification never reads the salt. Anyone who has the salt can test password guesses against the commitment.

## Building

Requires OpenSSL (`libcrypto`). On Linux, also requires `libbsd`.

```sh
make
make install
make test
```

## License

See [LICENSE](LICENSE).

## Author

Nami Arjmandi
