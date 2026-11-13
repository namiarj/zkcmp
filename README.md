# zkcmp

Prove that you hold a file or password matching a published commitment, without revealing it.

```sh
zkcmp -c release.tar release.tar.commit    # publish once
zkcmp -p release.tar release.tar.proof     # prove
zkcmp release.tar.commit release.tar.proof # verify
```

The commitment is derived from the file or password, and the proof is a Schnorr proof of knowledge of the value behind it. The verifier learns whether the proof is valid and nothing else. [Schnorr proofs](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/) explains the protocol.

Commitments are deterministic. If the secret is guessable, anyone can check a guess by recomputing the commitment, so use `-s` with a random salt for anything low-entropy. Proofs use fresh randomness and can be sent over any channel.

## Usage

```text
zkcmp -c [-h hash] [-s salt] file commit
zkcmp -p [-h hash] [-s salt] [-t seconds] file proof
zkcmp -C [-h hash] [-s salt] commit
zkcmp -P [-h hash] [-s salt] [-t seconds] proof
zkcmp -g salt
zkcmp [-q] [-h hash] [-t seconds] commit proof
```

`-h` selects `sha256` (default), `sha3-256`, or `sha512-256`. `-q` silences the mismatch message. Verification exits `0` on match, `1` on mismatch or expired proof, and `2` on error.

## Streaming a proof

A proof is a binary file, and `-` writes it to standard output, so it can go straight into another tool without touching disk:

```sh
zkcmp -p release.tar - | curl -sT - https://verifier.example/submit
zkcmp -p release.tar - | ssh verifier 'cat > alice.proof'
```

The secret stays on disk and is read directly by `zkcmp`.

## Multiple provers

```sh
server$ zkcmp -c release.tar release.tar.commit
alice$  zkcmp -p release.tar alice.proof
bob$    zkcmp -p release.tar bob.proof
server$ zkcmp release.tar.commit alice.proof
server$ zkcmp release.tar.commit bob.proof
```

Anyone holding `release.tar` can make a valid proof, so the file itself is the credential. Use `-s` if it should not be.

## Time-bound proofs

```sh
zkcmp -p -t 3600 release.tar release.tar.proof     # prover
zkcmp -t 3600 release.tar.commit release.tar.proof # verifier
```

Time is divided into windows of `seconds`, and the proof is bound to the window it was made in. It is accepted for at least `seconds` and at most twice that. Both sides must use the same `-t`.

## Passwords and salts

```sh
zkcmp -g user.salt                # one salt per user
zkcmp -s user.salt -C user.commit # register, asks twice
zkcmp -s user.salt -P user.proof  # authenticate, asks once
zkcmp user.commit user.proof      # verify
```

Salt files must be exactly 32 bytes. Verification never reads the salt. Anyone who knows the salt can check password guesses against the commitment, so share it only with the provers.

## Building

Requires OpenSSL (`libcrypto`), plus `libbsd` on Linux.

```sh
make
make install
```

## License

See [`LICENSE`](LICENSE).

## Author

Nami Arjmandi
