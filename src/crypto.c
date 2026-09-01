#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "zkcmp.h"

void
setup_group(struct zkcmp *z)
{
    BIGNUM *pm1;

    z->ctx = BN_CTX_new();
    z->p   = BN_new();
    z->q   = BN_new();
    z->g   = BN_new();
    if (!z->ctx || !z->p || !z->q || !z->g)
        errx(ERR_EXIT, "OpenSSL allocation failed");
    if (!BN_hex2bn(&z->p,prime_hex))
        errx(ERR_EXIT, "invalid group prime");
    pm1 = BN_dup(z->p);
    if (!pm1)
        errx(ERR_EXIT, "OpenSSL allocation failed");
    if (BN_sub_word(pm1, 1) != 1 || BN_rshift1(z->q, pm1) != 1 || BN_set_word(z->g, 2) != 1) {
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

/*
 * Encode a big number as bytes, big endian.
 */
int
bn_fixed(const BIGNUM *bn, unsigned char *dst, size_t len)
{
    size_t n;

    n = (size_t)BN_num_bytes(bn);
    if (n > len)
        return (-1);
    memset(dst, 0, len);
    if (n != 0)
        BN_bn2bin(bn, dst + len - n);
    return (0);
}

char *
b64_encode(const unsigned char *src, size_t len)
{
    char *dst;
    int n;

    dst = malloc(4 * ((len + 2) / 3) + 1);
    if (dst == NULL)
        return (NULL);
    n = EVP_EncodeBlock((unsigned char *)dst, src, (int)len);
    if (n < 0) {
        free(dst);
        return (NULL);
    }
    dst[n] = '\0';
    return (dst);
}

int
b64_decode(const char *src, unsigned char *dst, size_t dstlen)
{
    unsigned char tmp[B64_LEN];
    size_t n;
    int r;

    n = strlen(src);
    if (n == 0 || (n & 3) != 0)
        return (-1);
    if (n >= B64_LEN)
        return (-1);
    r = EVP_DecodeBlock(tmp, (const unsigned char *)src, (int)n);
    if (r < 0)
        return (-1);
    if (n >= 1 && src[n - 1] == '=')
        r--;
    if (n >= 2 && src[n - 2] == '=')
        r--;
    if ((size_t)r > dstlen)
        return (-1);
    memcpy(dst, tmp, (size_t)r);
    return (r);
}

int
hash_stream(FILE *fp, unsigned char digest[DIGEST_LEN], struct zkcmp *z)
{
    EVP_MD_CTX *md;
    unsigned char buf[IO_BUF_LEN];
    size_t n;
    unsigned int digest_len;

    md = EVP_MD_CTX_new();
    if (md == NULL)
        return (-1);
    if (EVP_DigestInit_ex(md, z->md, NULL) != 1) {
        EVP_MD_CTX_free(md);
        return (-1);
    }
    while ((n = fread(buf, 1, sizeof(buf), fp)) != 0) {
        if (EVP_DigestUpdate(md, buf, n) != 1) {
            EVP_MD_CTX_free(md);
            return (-1);
        }
    }
    if (ferror(fp)) {
        EVP_MD_CTX_free(md);
        return (-1);
    }
    if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1 || digest_len != DIGEST_LEN) {
        EVP_MD_CTX_free(md);
        return (-1);
    }
    EVP_MD_CTX_free(md);
    return (0);
}

int
hash_path(const char *path, unsigned char digest[DIGEST_LEN], struct zkcmp *z)
{
    FILE *fp;
    int fd;
    int result;

    if (strcmp(path, "-") == 0)
        return (hash_stream(stdin, digest, z));

    if (z->nofollow) {
        fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd == -1)
            return (-1);
        fp = fdopen(fd, "rb");
        if (fp == NULL) {
            close(fd);
            return (-1);
        }
    } else {
        fp = fopen(path, "rb");
        if (fp == NULL)
            return (-1);
    }
    result = hash_stream(fp, digest, z);
    fclose(fp);
    return (result);
}

/*
 * c = H(Y || R) mod q
 */
static int
challenge(struct zkcmp *z, const unsigned char *y, const unsigned char *r, BIGNUM *c)
{
    EVP_MD_CTX *md;
    unsigned char digest[DIGEST_LEN];
    unsigned int digest_len;

    md = EVP_MD_CTX_new();
    if (md == NULL)
        return (-1);
    if (EVP_DigestInit_ex(md, z->md, NULL) != 1)
        goto fail;
    if (EVP_DigestUpdate(md, y, GROUP_LEN) != 1)
        goto fail;
    if (EVP_DigestUpdate(md, r, GROUP_LEN) != 1)
        goto fail;
    if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1)
        goto fail;
    if (digest_len != DIGEST_LEN)
        goto fail;
    if (BN_bin2bn(digest, DIGEST_LEN, c) == NULL)
        goto fail;
    if (BN_mod(c, c, z->q, z->ctx) != 1)
        goto fail;
    EVP_MD_CTX_free(md);
    return (0);
fail:
    EVP_MD_CTX_free(md);
    return (-1);
}

/*
 * x = digest mod q
 * Y = g^x
 */
int
gen_commit(struct zkcmp *z, const unsigned char digest[DIGEST_LEN], unsigned char commit[COMMIT_LEN])
{
    BIGNUM *x;
    BIGNUM *y;
    int ok;

    x = BN_bin2bn(digest, DIGEST_LEN, NULL);
    y = BN_new();
    if (x == NULL || y == NULL) {
        BN_free(x);
        BN_free(y);
        return (-1);
    }
    ok = BN_mod(x, x, z->q, z->ctx);
    if (ok == 1)
        ok = BN_mod_exp(y, z->g, x, z->p, z->ctx);
    if (ok == 1)
        if (bn_fixed(y, commit, GROUP_LEN) != 0)
            ok = 0;
    BN_free(x);
    BN_free(y);
    return (ok == 1 ? 0 : -1);
}

/*
 * Schnorr proof
 */
int
gen_proof(struct zkcmp *z, const unsigned char digest[DIGEST_LEN], const unsigned char commit[COMMIT_LEN], unsigned char proof[PROOF_LEN])
{
    BIGNUM *x;
    BIGNUM *k;
    BIGNUM *r;
    BIGNUM *c;
    BIGNUM *cx;
    BIGNUM *zz;
    unsigned char rbuf[GROUP_LEN];
    int ok = -1;

    x  = BN_bin2bn(digest, DIGEST_LEN, NULL);
    k  = BN_new();
    r  = BN_new();
    c  = BN_new();
    cx = BN_new();
    zz = BN_new();
    if (!x || !k || !r || !c || !cx || !zz)
        goto out;
    /*
     * x = digest mod q
     */
    if (BN_mod(x, x, z->q, z->ctx) != 1)
        goto out;
    /*
     * Random Schnorr nonce
     */
    if (BN_rand_range(k, z->q) != 1)
        goto out;
    /*
     * R = g^k mod p
     */
    if (BN_mod_exp(r, z->g, k, z->p, z->ctx) != 1)
        goto out;
    if (bn_fixed(r, rbuf, GROUP_LEN) != 0)
        goto out;
    /*
     * c = H(Y || R) mod q
     */
    if (challenge(z, commit, rbuf, c) != 0)
        goto out;
    /*
     * z = k + c*x mod q
     */
    if (BN_mod_mul(cx, c, x, z->q, z->ctx) != 1)
        goto out;
    if (BN_mod_add(zz, k, cx, z->q, z->ctx) != 1)
        goto out;
    memcpy(proof, rbuf, GROUP_LEN);
    if (bn_fixed(zz, proof + GROUP_LEN, GROUP_LEN) != 0)
        goto out;
    ok = 0;
out:
    BN_free(x);
    BN_free(k);
    BN_free(r);
    BN_free(c);
    BN_free(cx);
    BN_free(zz);
    return (ok);
}

/*
 * g^z == R * Y^c mod p
 */
int
verify(struct zkcmp *z, const unsigned char commit[COMMIT_LEN], const unsigned char proof[PROOF_LEN])
{
    BIGNUM *y;
    BIGNUM *r;
    BIGNUM *zz;
    BIGNUM *c;
    BIGNUM *lhs;
    BIGNUM *yc;
    BIGNUM *rhs;
    int valid = 0;

    y  = BN_bin2bn(commit, GROUP_LEN, NULL);
    r  = BN_bin2bn(proof, GROUP_LEN, NULL);
    zz = BN_bin2bn(proof + GROUP_LEN, GROUP_LEN, NULL);
    c   = BN_new();
    lhs = BN_new();
    yc  = BN_new();
    rhs = BN_new();
    if (!y || !r || !zz || !c || !lhs || !yc || !rhs)
        goto out;
    /*
     * Reject malformed group elements.
     */
    if (BN_is_zero(y) || BN_cmp(y, z->p) >= 0)
        goto out;
    if (BN_is_zero(r) || BN_cmp(r, z->p) >= 0)
        goto out;
    if (BN_cmp(zz, z->q) >= 0)
        goto out;
    /*
     * c = H(Y || R)
     */
    if (challenge(z, commit, proof, c) != 0)
        goto out;
    /*
     * lhs = g^z
     */
    if (BN_mod_exp(lhs, z->g, zz, z->p, z->ctx) != 1)
        goto out;
    /*
     * Y^c
     */
    if (BN_mod_exp(yc, y, c, z->p, z->ctx) != 1)
        goto out;
    /*
     * rhs = R * Y^c
     */
    if (BN_mod_mul(rhs, r, yc, z->p, z->ctx) != 1)
        goto out;
    valid = (BN_cmp(lhs, rhs) == 0);
out:
    BN_free(y);
    BN_free(r);
    BN_free(zz);
    BN_free(c);
    BN_free(lhs);
    BN_free(yc);
    BN_free(rhs);
    return (valid);
}
