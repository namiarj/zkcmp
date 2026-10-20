#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr,	"usage: zkcmp [-h hash] -c file\n"
			"       zkcmp [-h hash] -p file\n"
			"       zkcmp [-s] [-h hash] commit proof\n");
	exit(ERR_EXIT);
}

static int
hash_file(const char *path, unsigned char digest[DIGEST_LEN],
	struct zkcmp *z)
{
	FILE *fp;
	unsigned char buf[IO_BUF_LEN];
	EVP_MD_CTX *h;
	size_t n;
	unsigned int digest_len;
	int ret = -1;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return ret;
	h = EVP_MD_CTX_new();
	if (h == NULL)
		goto clean;
	if (EVP_DigestInit_ex(h, z->h, NULL) != 1)
		goto clean_h;
	if (EVP_DigestUpdate(h, DOMAIN_SEPARATOR, sizeof(DOMAIN_SEPARATOR)) != 1)
		goto clean_h;
	while ((n = fread(buf, 1, sizeof(buf), fp)) != 0)
		if (EVP_DigestUpdate(h, buf, n) != 1)
			goto clean_h;
	if (ferror(fp))
		goto clean_h;
	if (EVP_DigestFinal_ex(h, digest, &digest_len) != 1)
		goto clean_h;
	if (digest_len != DIGEST_LEN)
		goto clean_h;
	ret = 0;
clean_h:
	EVP_MD_CTX_free(h);
clean:
	fclose(fp);
	return ret;
}

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

int
main(int argc, char **argv)
{
	struct zkcmp z = { .h = EVP_sha256() };
	int ch;
	char cmd = 0;
	const char *file;
	int silent = 0;

#ifdef __OpenBSD__
	if (pledge("stdio rpath", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "c:p:h:s")) != -1) {
		switch (ch) {
		case 'c':
		case 'p':
			if (cmd)
				usage();
			cmd = ch;
			file = optarg;
			break;
		case 'h':
			if (!strcmp(optarg, "sha512-256"))
				z.h = EVP_sha512_256();
			else if (!strcmp(optarg, "sha3-256"))
				z.h = EVP_sha3_256();
			else if (strcmp(optarg, "sha256"))
				usage();
			break;
		case 's':
			silent = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	switch (argc) {
	case 0:
		switch (cmd) {
		case 'c':
			return commit_file(&z, file);
		case 'p':
			return prove_file(&z, file);
		}
		break;
	case 2:
		switch (cmd) {
		case 0:
			argv += optind;
			return verify_file(&z, argv[0], argv[1], silent);
		}
	}
	usage();
}
