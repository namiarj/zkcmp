#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

static void
init_group(struct zkcmp *z)
{
	BIGNUM *pm1;

	z->ctx = BN_CTX_new();
	z->q = BN_new();
	z->g = BN_new();
	if (z->ctx == NULL || z->q == NULL || z->g == NULL)
		errx(ERR_EXIT, "OpenSSL allocation failed");
	z->p = BN_bin2bn(prime, sizeof(prime), NULL);
	if (z->p == NULL)
		errx(ERR_EXIT, "OpenSSL allocation failed");
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

static void
free_group(struct zkcmp *z)
{
	BN_free(z->p);
	BN_free(z->q);
	BN_free(z->g);
	BN_CTX_free(z->ctx);
}

static int
hash_file(const char *path, unsigned char digest[DIGEST_LEN],
	struct zkcmp *z)
{
	FILE *fp;
	unsigned char buf[IO_BUF_LEN];
	EVP_MD_CTX *md;
	size_t n;
	unsigned int digest_len;
	int ret = -1;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return ret;
	md = EVP_MD_CTX_new();
	if (md == NULL)
		goto clean;
	if (EVP_DigestInit_ex(md, z->md, NULL) != 1)
		goto clean_md;
	if (EVP_DigestUpdate(md, DOMAIN_SEPARATOR, sizeof(DOMAIN_SEPARATOR)) != 1)
		goto clean_md;
	while ((n = fread(buf, 1, sizeof(buf), fp)) != 0)
		if (EVP_DigestUpdate(md, buf, n) != 1)
			goto clean_md;
	if (ferror(fp))
		goto clean_md;
	if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1)
		goto clean_md;
	if (digest_len != DIGEST_LEN)
		goto clean_md;
	ret = 0;
clean_md:
	EVP_MD_CTX_free(md);
clean:
	fclose(fp);
	return ret;
}

static void
print_base64(const unsigned char *data, const int len)
{
	char encoded[B64_LEN];
	if (EVP_EncodeBlock((unsigned char *)encoded, data, len) < 0)
		errx(ERR_EXIT, "base64 encoding failed");
	puts(encoded);
}

int
commit_file(struct zkcmp *z, const char *file)
{
	unsigned char digest[DIGEST_LEN];
	unsigned char commitment[GROUP_LEN];

	init_group(z);
	if (hash_file(file, digest, z) != 0)
		err(ERR_EXIT, "failed to hash %s", file);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	if (commit(z, digest, commitment) != 0)
		errx(ERR_EXIT, "commitment generation failed");
	free_group(z);
	print_base64(commitment, sizeof(commitment));
	return OK_EXIT;
}

int
prove_file(struct zkcmp *z, const char *file)
{
	unsigned char digest[DIGEST_LEN];
	unsigned char commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];

	init_group(z);
	if (hash_file(file, digest, z) != 0)
		err(ERR_EXIT, "failed to hash %s", file);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	if (commit(z, digest, commitment) != 0)
		errx(ERR_EXIT, "commitment generation failed");
	if (prove(z, digest, commitment, proof) != 0)
		errx(ERR_EXIT, "proof generation failed");
	free_group(z);
	print_base64(proof, sizeof(proof));
	return OK_EXIT;
}

int
verify_file(struct zkcmp *z, const char *commit_path, const char *proof_path,
	const int silent)
{
	unsigned char commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];
	char commitment_buf[B64_LEN];
	char proof_buf[B64_LEN];
	FILE *fp;
	int status;

	fp = fopen(commit_path, "r");
	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", commit_path);
	if (fgets(commitment_buf, sizeof(commitment_buf), fp) == NULL) {
		fclose(fp);
		errx(ERR_EXIT, "failed to read %s", commit_path);
	}
	fclose(fp);
	fp = fopen(proof_path, "r");
	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", proof_path);
	if (fgets(proof_buf, sizeof(proof_buf), fp) == NULL) {
		fclose(fp);
		errx(ERR_EXIT, "failed to read %s", proof_path);
	}
	fclose(fp);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	init_group(z);
	if (EVP_DecodeBlock(commitment, (unsigned char *)commitment_buf,
		(int)strlen(commitment_buf)) != GROUP_LEN)
			errx(ERR_EXIT, "invalid commitment");
	if (EVP_DecodeBlock(proof, (unsigned char *)proof_buf,
		(int)strlen(proof_buf)) != GROUP_LEN * 2)
			errx(ERR_EXIT, "invalid proof");
	status = verify(z, commitment, proof);
	if (status == DIFF_EXIT && !silent)
		warnx("commitment and proof mismatched");
	free_group(z);
	return status;
}
