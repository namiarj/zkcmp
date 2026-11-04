#ifndef ZKCMP_H
#define ZKCMP_H

#include <stdint.h>

#if defined(__linux__)
#include <endian.h>
#else
#include <sys/endian.h>
#endif

#include <openssl/bn.h>
#include <openssl/evp.h>

#define OK_EXIT		0
#define DIFF_EXIT	1
#define ERR_EXIT	2

#define DOMAIN_SEPARATOR "zkcmp-domain-separator"
#define DIGEST_LEN	32
#define COMMIT_LEN	384
#define PROOF_LEN	(COMMIT_LEN * 2)
#define IO_BUF_LEN	16384
#define PW_ITER		600000
#define PW_MAX		1024

struct zkcmp {
	const EVP_MD *h;
	uint64_t window;
	BIGNUM *p, *q, *g;
	BN_CTX *ctx;
};

int commit(struct zkcmp*, const unsigned char[DIGEST_LEN],
    unsigned char[COMMIT_LEN]);
int prove(struct zkcmp*, const unsigned char[DIGEST_LEN],
    const unsigned char[COMMIT_LEN], unsigned char[PROOF_LEN]);
int verify(struct zkcmp*, const unsigned char[COMMIT_LEN],
    const unsigned char[PROOF_LEN]);

#endif
