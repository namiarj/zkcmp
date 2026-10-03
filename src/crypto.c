/*
 * Schnorr Zero-Knowledge Proof
 *
 * x = H(file) mod q
 * Y = g^x mod p
 *
 * k <- random Zq
 * R = g^k
 * c = H(Y || R) mod q
 * z = k + c*x mod q
 *
 * g^z == R * Y^c mod p
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>`
#include <unistd.h>

#include "zkcmp.h"

void
setup_group(struct zkcmp *z)
{
	BIGNUM *pm1;

	z->ctx = BN_CTX_new();
	z->p = BN_new();
	z->q = BN_new();
	z->g = BN_new();

	if (z->ctx == NULL || z->p == NULL ||
		z->q == NULL || z->g == NULL)
		errx(ERR_EXIT, "OpenSSL allocation failed");

	if (BN_hex2bn(&z->p, prime_hex) == 0)
		errx(ERR_EXIT, "invalid group prime");

	pm1 = BN_dup(z->p);
	if (pm1 == NULL)
		errx(ERR_EXIT, "OpenSSL allocation failed");

	if (BN_sub_word(pm1, 1) != 1 ||
		BN_rshift1(z->q, pm1) != 1 ||
		BN_set_word(z->g, 2) != 1) {
		BN_free(pm1);
		errx(ERR_EXIT, "group initialization failed");
	}

	BN_free(pm1);
}

void
free_group(struct zkcmp *z)
{
	BN_free(z->p);
	BN_free(z->q);
	BN_free(z->g);
	BN_CTX_free(z->ctx);
}

static int
bn_fixed(const BIGNUM *bn, unsigned char *dst, size_t len)
{
	size_t n;

	n = (size_t)BN_num_bytes(bn);
	if (n > len)
		return -1;

	memset(dst, 0, len);

	if (n != 0)
		BN_bn2bin(bn, dst + len - n);

	return 0;
}

int
hash_path(const char *path, unsigned char digest[DIGEST_LEN],
	struct zkcmp *z)
{
	FILE *fp;
	unsigned char buf[IO_BUF_LEN];
	EVP_MD_CTX *md;
	size_t n;
	unsigned int digest_len;
	int fd = -1;
	int ret = -1;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;

	md = EVP_MD_CTX_new();
	if (md == NULL)
		goto out;

	if (EVP_DigestInit_ex(md, z->md, NULL) != 1)
		goto out_md;

	while ((n = fread(buf, 1, sizeof(buf), fp)) != 0) {
		if (EVP_DigestUpdate(md, buf, n) != 1)
			goto out_md;
	}

	if (ferror(fp))
		goto out_md;

	if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1)
		goto out_md;

	if (digest_len != DIGEST_LEN)
		goto out_md;

	ret = 0;

out_md:
	EVP_MD_CTX_free(md);
out:
	fclose(fp);
	return ret;
}

int
commit(struct zkcmp *z, const unsigned char digest[DIGEST_LEN],
	unsigned char commitment[GROUP_LEN])
{
	BIGNUM *x;
	BIGNUM *y;
	int ok;

	x = BN_bin2bn(digest, DIGEST_LEN, NULL);
	y = BN_new();

	if (x == NULL || y == NULL) {
		BN_clear_free(x);
		BN_free(y);
		return -1;
	}

	ok = BN_mod(x, x, z->q, z->ctx);

	if (ok == 1)
		ok = BN_mod_exp(y, z->g, x, z->p, z->ctx);

	if (ok == 1)
		ok = bn_fixed(y, commitment, GROUP_LEN) == 0;

	BN_clear_free(x);
	BN_free(y);

	return ok ? 0 : -1;
}

static int
challenge(struct zkcmp *z, const unsigned char *y,
	const unsigned char *r, BIGNUM *c)
{
	EVP_MD_CTX *md;
	unsigned char digest[DIGEST_LEN];
	unsigned int digest_len;
	int ret = -1;

	md = EVP_MD_CTX_new();
	if (md == NULL)
		return -1;

	if (EVP_DigestInit_ex(md, z->md, NULL) != 1)
		goto out;

	if (EVP_DigestUpdate(md, y, GROUP_LEN) != 1)
		goto out;

	if (EVP_DigestUpdate(md, r, GROUP_LEN) != 1)
		goto out;

	if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1)
		goto out;

	if (digest_len != DIGEST_LEN)
		goto out;

	if (BN_bin2bn(digest, DIGEST_LEN, c) == NULL)
		goto out;

	if (BN_mod(c, c, z->q, z->ctx) != 1)
		goto out;

	ret = 0;

out:
	EVP_MD_CTX_free(md);
	return ret;
}

int
prove(struct zkcmp *z, const unsigned char digest[DIGEST_LEN],
	const unsigned char commitment[GROUP_LEN],
	unsigned char proof[GROUP_LEN * 2])
{
	BIGNUM *x;
	BIGNUM *k;
	BIGNUM *r;
	BIGNUM *c;
	BIGNUM *cx;
	BIGNUM *zz;
	unsigned char rbuf[GROUP_LEN];
	int ret = -1;

	x = BN_bin2bn(digest, DIGEST_LEN, NULL);
	k = BN_new();
	r = BN_new();
	c = BN_new();
	cx = BN_new();
	zz = BN_new();

	if (x == NULL || k == NULL || r == NULL ||
		c == NULL || cx == NULL || zz == NULL)
		goto out;

	if (BN_mod(x, x, z->q, z->ctx) != 1)
		goto out;

	if (BN_rand_range(k, z->q) != 1)
		goto out;

	if (BN_mod_exp(r, z->g, k, z->p, z->ctx) != 1)
		goto out;

	if (bn_fixed(r, rbuf, GROUP_LEN) != 0)
		goto out;

	if (challenge(z, commitment, rbuf, c) != 0)
		goto out;

	if (BN_mod_mul(cx, c, x, z->q, z->ctx) != 1)
		goto out;

	if (BN_mod_add(zz, k, cx, z->q, z->ctx) != 1)
		goto out;

	memcpy(proof, rbuf, GROUP_LEN);

	if (bn_fixed(zz, proof + GROUP_LEN, GROUP_LEN) != 0)
		goto out;

	ret = 0;

out:
	BN_clear_free(x);
	BN_clear_free(k);
	BN_free(r);
	BN_free(c);
	BN_clear_free(cx);
	BN_clear_free(zz);

	return ret;
}

int
verify(struct zkcmp *z, const unsigned char commitment[GROUP_LEN],
	const unsigned char proof[GROUP_LEN * 2])
{
	BIGNUM *y;
	BIGNUM *r;
	BIGNUM *zz;
	BIGNUM *c;
	BIGNUM *lhs;
	BIGNUM *yc;
	BIGNUM *rhs;
	int valid = 0;

	y = BN_bin2bn(commitment, GROUP_LEN, NULL);
	r = BN_bin2bn(proof, GROUP_LEN, NULL);
	zz = BN_bin2bn(proof + GROUP_LEN, GROUP_LEN, NULL);
	c = BN_new();
	lhs = BN_new();
	yc = BN_new();
	rhs = BN_new();

	if (y == NULL || r == NULL || zz == NULL ||
		c == NULL || lhs == NULL || yc == NULL || rhs == NULL)
		goto out;

	if (BN_is_zero(y) || BN_cmp(y, z->p) >= 0)
		goto out;

	if (BN_is_zero(r) || BN_cmp(r, z->p) >= 0)
		goto out;

	if (BN_cmp(zz, z->q) >= 0)
		goto out;

	if (challenge(z, commitment, proof, c) != 0)
		goto out;

	if (BN_mod_exp(lhs, z->g, zz, z->p, z->ctx) != 1)
		goto out;

	if (BN_mod_exp(yc, y, c, z->p, z->ctx) != 1)
		goto out;

	if (BN_mod_mul(rhs, r, yc, z->p, z->ctx) != 1)
		goto out;

	valid = BN_cmp(lhs, rhs) == 0;

out:
	BN_free(y);
	BN_free(r);
	BN_free(zz);
	BN_free(c);
	BN_free(lhs);
	BN_free(yc);
	BN_free(rhs);

	return valid;
}
