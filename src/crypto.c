/*
 * Y = g^x mod p, x = H(secret) mod q
 * R = g^k mod p, c = H(Y || R [|| window]) mod q, s = k + c*x mod q
 * verify: g^s == R * Y^c mod p
 */
#include <string.h>

#include "zkcmp.h"

int
commit(struct zkcmp *z, const unsigned char digest[DIGEST_LEN],
    unsigned char commitment[GROUP_LEN])
{
	BIGNUM *x = BN_bin2bn(digest, DIGEST_LEN, NULL);
	BIGNUM *y = BN_new();
	int ret = -1;

	if (x && y && BN_mod(x, x, z->q, z->ctx) == 1 &&
	    BN_mod_exp(y, z->g, x, z->p, z->ctx) == 1 &&
	    BN_bn2binpad(y, commitment, GROUP_LEN) == GROUP_LEN)
		ret = 0;
	BN_clear_free(x);
	BN_free(y);
	return ret;
}

static int
challenge(const struct zkcmp *z, const unsigned char y[GROUP_LEN],
    const unsigned char r[GROUP_LEN], BIGNUM *c)
{
	EVP_MD_CTX *h = EVP_MD_CTX_new();
	uint64_t be = htobe64(z->window);
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	int ok = h != NULL &&
	    EVP_DigestInit_ex(h, z->h, NULL) == 1 &&
	    EVP_DigestUpdate(h, y, GROUP_LEN) == 1 &&
	    EVP_DigestUpdate(h, r, GROUP_LEN) == 1;

	if (ok && z->window != 0)
		ok = EVP_DigestUpdate(h, &be, sizeof(be)) == 1;
	ok = ok && EVP_DigestFinal_ex(h, md, &len) == 1 &&
	    len == DIGEST_LEN && BN_bin2bn(md, DIGEST_LEN, c) != NULL &&
	    BN_mod(c, c, z->q, z->ctx) == 1;
	EVP_MD_CTX_free(h);
	return ok ? 0 : -1;
}

int
prove(struct zkcmp *z, const unsigned char digest[DIGEST_LEN],
    const unsigned char commitment[GROUP_LEN],
    unsigned char proof[PROOF_LEN])
{
	BIGNUM *x = BN_bin2bn(digest, DIGEST_LEN, NULL);
	BIGNUM *k = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *c = BN_new();
	unsigned char rb[GROUP_LEN];
	int ret = -1;

	if (x && k && r && c &&
	    BN_mod(x, x, z->q, z->ctx) == 1 &&
	    BN_rand_range(k, z->q) == 1 &&
	    BN_mod_exp(r, z->g, k, z->p, z->ctx) == 1 &&
	    BN_bn2binpad(r, rb, GROUP_LEN) == GROUP_LEN &&
	    challenge(z, commitment, rb, c) == 0 &&
	    BN_mod_mul(c, c, x, z->q, z->ctx) == 1 &&
	    BN_mod_add(c, c, k, z->q, z->ctx) == 1 &&
	    BN_bn2binpad(c, proof + GROUP_LEN, GROUP_LEN) == GROUP_LEN) {
		memcpy(proof, rb, GROUP_LEN);
		ret = 0;
	}
	BN_clear_free(x);
	BN_clear_free(k);
	BN_free(r);
	BN_clear_free(c);
	return ret;
}

int
verify(struct zkcmp *z, const unsigned char commitment[GROUP_LEN],
    const unsigned char proof[PROOF_LEN])
{
	BIGNUM *y = BN_bin2bn(commitment, GROUP_LEN, NULL);
	BIGNUM *r = BN_bin2bn(proof, GROUP_LEN, NULL);
	BIGNUM *s = BN_bin2bn(proof + GROUP_LEN, GROUP_LEN, NULL);
	BIGNUM *c = BN_new();
	BIGNUM *lhs = BN_new();
	BIGNUM *rhs = BN_new();
	int ret = DIFF_EXIT;

	if (y && r && s && c && lhs && rhs &&
	    !BN_is_zero(y) && BN_cmp(y, z->p) < 0 &&
	    !BN_is_zero(r) && BN_cmp(r, z->p) < 0 &&
	    BN_cmp(s, z->q) < 0 &&
	    BN_mod_exp(c, y, z->q, z->p, z->ctx) == 1 && BN_is_one(c) &&
	    challenge(z, commitment, proof, c) == 0 &&
	    BN_mod_exp(lhs, z->g, s, z->p, z->ctx) == 1 &&
	    BN_mod_exp(rhs, y, c, z->p, z->ctx) == 1 &&
	    BN_mod_mul(rhs, rhs, r, z->p, z->ctx) == 1)
		ret = BN_cmp(lhs, rhs) == 0 ? OK_EXIT : DIFF_EXIT;

	BN_free(y);
	BN_free(r);
	BN_free(s);
	BN_free(c);
	BN_free(lhs);
	BN_free(rhs);
	return ret;
}
