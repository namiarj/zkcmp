#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr,	"usage: zkcmp [-h hash] [-s psk] -c file -o commit\n"
			"       zkcmp [-h hash] [-s psk] -p file -o proof\n"
			"       zkcmp -g psk\n"
			"       zkcmp [-q] [-h hash] [-s psk] commit proof\n");
	exit(ERR_EXIT);
}

static int
hash_file(struct zkcmp *z, const char *file, unsigned char digest[DIGEST_LEN])
{
	FILE *fp;
	unsigned char buf[IO_BUF_LEN];
	EVP_MD_CTX *h;
	size_t n;
	unsigned int digest_len;
	int ret = -1;

	fp = fopen(file, "rb");
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
	if (fclose(fp))
		ret = -1;
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

int
write_file(const char *file, const unsigned char *buf, const unsigned long len)
{
	FILE *fp;

	fp = fopen(file, "wb");
	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	if (fwrite(buf, 1, len, fp) != len)
		err(ERR_EXIT, "failed to write %s", file);
	if (fclose(fp) == EOF)
		err(ERR_EXIT, "failed to close %s", file);
	return OK_EXIT;
}

int
commit_file(struct zkcmp *z, const char *file, const char *o_file)
{
	unsigned char digest[DIGEST_LEN];
	unsigned char commitment[GROUP_LEN];

	init_group(z);
	if (hash_file(z, file, digest) != 0)
		err(ERR_EXIT, "failed to hash %s", file);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	if (commit(z, digest, commitment) != 0)
		errx(ERR_EXIT, "commitment generation failed");
	free_group(z);
	write_file(o_file, commitment, GROUP_LEN);
	return OK_EXIT;
}

int
prove_file(struct zkcmp *z, const char *file, const char *o_file)
{
	unsigned char digest[DIGEST_LEN];
	unsigned char commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];

	init_group(z);
	if (hash_file(z, file, digest) != 0)
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
	write_file(o_file, proof, GROUP_LEN * 2);
	return OK_EXIT;
}

int
verify_file(struct zkcmp *z, const char *commit_file, const char *proof_file,
	const int quiet)
{
	unsigned char commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];
	FILE *fp;
	int status;

	fp = fopen(commit_file, "rb");
	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", commit_file);
	if (fread(commitment, 1, sizeof(commitment), fp) != sizeof(commitment) || fgetc(fp) != EOF || ferror(fp)) {
		fclose(fp);
		errx(ERR_EXIT, "invalid file size or read error: %s", commit_file);
	}
	if (fclose(fp))
		err(ERR_EXIT, "failed to close %s", commit_file);

	fp = fopen(proof_file, "rb");
	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", proof_file);
	if (fread(proof, 1, sizeof(proof), fp) != sizeof(proof) || fgetc(fp) != EOF || ferror(fp)) {
		fclose(fp);
		errx(ERR_EXIT, "invalid file size or read error: %s", proof_file);
	}
	if (fclose(fp))
		err(ERR_EXIT, "failed to close %s", proof_file);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	init_group(z);
	status = verify(z, commitment, proof);
	free_group(z);
	if (status == DIFF_EXIT && !quiet)
		warnx("commitment and proof mismatched");
	return status;
}

int
gen_psk(const char *file)
{
	unsigned char buf[GEN_PSK_LEN];

	arc4random_buf(buf, sizeof(buf));
	write_file(file, buf, sizeof(buf));
	explicit_bzero(buf, sizeof(buf));
	return OK_EXIT;
}

int
main(int argc, char **argv)
{
	struct zkcmp z = { .h = EVP_sha256() };
	int ch;
	char cmd = 0;
	const char *file;
	const char *o_file = NULL;
	int quiet = 0;

#ifdef __OpenBSD__
	if (pledge("stdio rpath", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "c:p:g:o:h:q")) != -1) {
		switch (ch) {
		case 'c':
		case 'p':
		case 'g':
			if (cmd)
				usage();
			cmd = ch;
			file = optarg;
			break;
		case 'o':
			o_file = optarg;
			break;
		case 'h':
			if (!strcmp(optarg, "sha512-256"))
				z.h = EVP_sha512_256();
			else if (!strcmp(optarg, "sha3-256"))
				z.h = EVP_sha3_256();
			else if (strcmp(optarg, "sha256"))
				usage();
			break;
		case 'q':
			quiet = 1;
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
			return commit_file(&z, file, o_file);
		case 'p':
			return prove_file(&z, file, o_file);
		case 'g':
			return gen_psk(file);
		}
		break;
	case 2:
		switch (cmd) {
		case 0:
			argv += optind;
			return verify_file(&z, argv[0], argv[1], quiet);
		}
	}
	usage();
}
