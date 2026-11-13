#!/bin/sh
# tests/run.sh: zkcmp file-mode regression tests
# usage: make test
#        ZKCMP=/path/to/zkcmp sh tests/run.sh
#        GENERATE=1 make test    # first run: record the known-answer vector

Z=$(cd "$(dirname "${ZKCMP:-./zkcmp}")" && pwd)/$(basename "${ZKCMP:-./zkcmp}")
ROOT=$(cd "$(dirname "$0")" && pwd)
VEC=$ROOT/vectors
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT INT TERM
pass=0 fail=0

ok() {   # ok "name" command...
	name=$1; shift
	if "$@" >/dev/null 2>&1; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1)); echo "FAIL: $name"
	fi
}
code() { # code WANT "name" command...
	want=$1; name=$2; shift 2
	"$@" >/dev/null 2>&1; got=$?
	if [ "$got" -eq "$want" ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1)); echo "FAIL: $name (exit $got, want $want)"
	fi
}

cd "$T" || exit 1
printf 'secret data\n' > f
printf 'other data\n'  > g
printf 'AAAAAAAA' > bad.salt

# Round trip and mismatch
ok   "commit+prove+verify" sh -c "$Z -c f f.commit && $Z -p f f.proof && $Z f.commit f.proof"
code 1 "wrong file fails"  sh -c "$Z -c g g.commit && $Z -p g g.proof && $Z f.commit g.proof"
code 1 "proof for other commit fails" sh -c "$Z -c g g.commit && $Z g.commit f.proof"

# Determinism of commitments, freshness of proofs
ok   "commit deterministic" sh -c "$Z -c f c1 && $Z -c f c2 && cmp -s c1 c2"
ok   "proofs are fresh"     sh -c "$Z -p f p1 && $Z -p f p2 && ! cmp -s p1 p2"

# Hash selection: the verifier must use the same -h
ok   "sha3-256 round trip" sh -c "$Z -h sha3-256 -c f h.commit && $Z -h sha3-256 -p f h.proof && $Z -h sha3-256 h.commit h.proof"
code 1 "hash mismatch fails" sh -c "$Z -h sha3-256 -c f h2.commit && $Z -p f h2.proof && $Z -h sha3-256 h2.commit h2.proof"

# Salt
$Z -g salt.bin
ok   "salt is 32 bytes"    sh -c "[ \$(wc -c < salt.bin) -eq 32 ]"
ok   "salt mode 0600"      sh -c "[ \$(stat -c %a salt.bin 2>/dev/null || stat -f %Lp salt.bin) = 600 ]"
ok   "salt changes commit" sh -c "$Z -s salt.bin -c f s.commit && ! cmp -s s.commit c1"
code 2 "bad salt size"     $Z -s bad.salt -c f x.commit
code 1 "wrong salt fails"  sh -c "$Z -g salt2.bin && $Z -s salt.bin -c f s2.commit && $Z -s salt.bin -p f s2.proof && $Z -s salt2.bin -c f s3.commit && $Z s3.commit s2.proof"

# Stdout proof streams and verifies
ok   "stdout proof verifies" sh -c "$Z -p f - > sp && $Z c1 sp"

# Tampering (assumes PROOF_LEN > 41)
ok   "tamper detection" sh -c "
	cp p1 tp && printf '\\377' | dd of=tp bs=1 seek=40 conv=notrunc 2>/dev/null
	! $Z c1 tp 2>/dev/null"

# Quiet flag: needs a real proof for a different file
code 1 "quiet mismatch" $Z -q c1 g.proof
ok   "quiet suppresses stderr" sh -c "! $Z -q c1 g.proof 2>&1 | grep -q ."

# Usage errors
code 2 "no args"       $Z
code 2 "bad hash name" $Z -h md5 -c f x
code 2 "two commands"  $Z -c -p f x

# Time windows (about 6 seconds)
ok   "timed proof verifies now" sh -c "$Z -p -t 2 f tp2 && $Z -t 2 c1 tp2"
code 1 "timed proof needs -t"   sh -c "$Z -p -t 2 f tp3 && $Z c1 tp3"
sleep 5
code 1 "timed proof expires"    $Z -t 2 c1 tp2

# Known-answer vector: the commitment for a fixed input must not change
printf 'vector input\n' > kat.in
if [ -n "$GENERATE" ]; then
	mkdir -p "$VEC" && cp kat.in "$VEC/kat.in" && "$Z" -c "$VEC/kat.in" "$VEC/kat.commit"
	echo "generated $VEC/kat.commit (review before committing)"
elif [ -f "$VEC/kat.commit" ]; then
	ok "known-answer commit unchanged" sh -c "$Z -c '$VEC/kat.in' kat.new && cmp -s '$VEC/kat.commit' kat.new"
else
	echo "SKIP: no $VEC/kat.commit (run with GENERATE=1 once)"
fi

echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
