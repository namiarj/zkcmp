# zkcmp

**Zero-knowledge file possession and comparison utility.**

`zkcmp` is a minimal Unix utility exploring whether knowledge of a file-derived secret can be demonstrated without revealing the file itself.

## Status

> **Experimental / exploratory software.**
>
> The protocol and implementation are still evolving. Do not rely on `zkcmp` for security-critical applications, authentication, or protection of valuable secrets.

## How it works

`zkcmp` derives a secret (hash) from a file:

```text
file
  |
  v
hash
  |
  v
secret
  |
  v
commitment
  |
  v
zero-knowledge proof
```

The proof is constructed so that the secret itself does not need to be transmitted.

The current implementation uses a Schnorr-style proof of knowledge over a 3072-bit MODP group.

The default hash is SHA-256. SHA3-256 or BLAKE2s-256 can also be selected.

## Commands

`zkcmp` provides four operations:

```text
zkcmp commit file
zkcmp prove file
zkcmp verify commit proof
zkcmp check file proof
```

### `commit`

Creates a reusable public commitment from a file.

```sh
zkcmp commit release.tar > commit
```

A commitment can be published once and used as the public statement for multiple independent proofs.

### `prove`

Creates a proof from a local file.

```sh
zkcmp prove release.tar > proof
```

### `verify`

Verifies a proof against a previously created commitment.

```sh
zkcmp verify commit proof
```

This is useful when a commitment has been published and multiple parties need to demonstrate knowledge of the corresponding secret.

For example:

```sh
server$ zkcmp commit release.tar > commit

alice$ zkcmp prove release.tar > alice.proof
bob$   zkcmp prove release.tar > bob.proof

server$ zkcmp verify commit alice.proof
server$ zkcmp verify commit bob.proof
```

### `check`

Checks the supplied proof against a local file.

The intended Unix/SSH workflow is:

```sh
zkcmp prove release.tar | ssh host 'zkcmp check release.tar -'
```

## Linkability

The current commitment is deterministic.

The same file produces the same commitment when the same hash algorithm is used.

A published commitment can therefore act as a stable identifier.

An observer can recognize repeated use of the same commitment and, if they possess candidate files, can test those candidates against it.

Therefore:

> **A `zkcmp` commitment should not be considered an unlinkable or strongly hiding commitment.**

A proof can therefore provide a zero-knowledge property while the public statement to which it refers remains linkable.

If a reusable public statement is not needed, the `check` workflow avoids publishing the commitment as a separate object.

## Building

On FreeBSD:

```sh
make
make install
```

## License

See [`LICENSE`](LICENSE) for licensing information.

## Author

Nami Arjmandi
