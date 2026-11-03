#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <bsd/readpassphrase.h>
#include <bsd/stdlib.h>
#else
#include <readpassphrase.h>
#endif

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr, "usage: zkcmp [-h hash] [-s salt] -c file -o commit\n"
	    "       zkcmp [-h hash] [-s salt] -p file [-t seconds] -o proof\n"
	    "       zkcmp [-h hash] [-s salt] -C -o commit\n"
	    "       zkcmp [-h hash] [-s salt] -P [-t seconds] -o proof\n"
	    "       zkcmp -g salt\n"
	    "       zkcmp [-q] [-h hash] [-t seconds] commit proof\n");
	exit(ERR_EXIT);
}

static void
guard(int ok, const char *what)
{
	if (!ok)
		errx(ERR_EXIT, "%s failed", what);
}

static uint64_t
parse_u64(const char *s)
{
	char *end;
	unsigned long long v;

	if (!isdigit((unsigned char)*s))
		errx(ERR_EXIT, "invalid number: %s", s);
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || *end != '\0' || v == 0)
		errx(ERR_EXIT, "invalid number: %s", s);
	return (uint64_t)v;
}

static uint64_t
window_of(time_t now, uint64_t secs)
{
	return (uint64_t)now / secs + 1;
}

static FILE *
create_file(const char *file)
{
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	FILE *fp = (fd == -1) ? NULL : fdopen(fd, "wb");

	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	return fp;
}

static void
write_file(FILE *fp, const char *file, const void *buf, size_t len)
{
	if (fwrite(buf, 1, len, fp) != len || fclose(fp))
		err(ERR_EXIT, "failed to write %s", file);
}

static size_t
read_file(const char *file, void *buf, size_t cap)
{
	FILE *fp = fopen(file, "rb");
	size_t n;

	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	n = fread(buf, 1, cap, fp);
	if (ferror(fp) || fgetc(fp) != EOF)
		errx(ERR_EXIT, "invalid file size or read error: %s", file);
	fclose(fp);
	return n;
}

static void
read_password(unsigned char key[DIGEST_LEN], const char *s_file, int confirm)
{
	unsigned char salt[DIGEST_LEN] = { 0 };
	char pw[PW_MAX], pw2[PW_MAX];

	if (s_file && read_file(s_file, salt, sizeof(salt)) != sizeof(salt))
		errx(ERR_EXIT, "invalid salt size: %s", s_file);
	guard(readpassphrase("Password: ", pw, sizeof(pw), RPP_ECHO_OFF) &&
	    *pw, "password input");
	guard(!confirm || (readpassphrase("Confirm password: ", pw2,
	    sizeof(pw2), RPP_ECHO_OFF) && strcmp(pw, pw2) == 0),
	    "password confirmation");
	guard(PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt,
	    s_file ? sizeof(salt) : 0, PW_ITER, EVP_sha512(), DIGEST_LEN, key),
	    "key derivation");
	explicit_bzero(pw, sizeof(pw));
	explicit_bzero(pw2, sizeof(pw2));
}

static void
hash_file(EVP_MD_CTX *h, const char *file)
{
	unsigned char buf[IO_BUF_LEN];
	FILE *fp = fopen(file, "rb");
	size_t n;

	if (fp == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	while ((n = fread(buf, 1, sizeof(buf), fp)) != 0)
		guard(EVP_DigestUpdate(h, buf, n) == 1, "hashing");
	if (ferror(fp))
		errx(ERR_EXIT, "read error: %s", file);
	explicit_bzero(buf, sizeof(buf));
	fclose(fp);
}

static void
derive_digest(const struct zkcmp *z, const char *file, const char *s_file,
    int confirm, unsigned char digest[DIGEST_LEN])
{
	unsigned char key[DIGEST_LEN];
	EVP_MD_CTX *h = EVP_MD_CTX_new();
	unsigned int len = 0;

	guard(h && EVP_DigestInit_ex(h, z->h, NULL) == 1 &&
	    EVP_DigestUpdate(h, DOMAIN_SEPARATOR, sizeof(DOMAIN_SEPARATOR)) == 1,
	    "hashing");
	if (file) {
		if (s_file)
			hash_file(h, s_file);
		hash_file(h, file);
	} else {
		read_password(key, s_file, confirm);
		guard(EVP_DigestUpdate(h, key, sizeof(key)) == 1, "hashing");
		explicit_bzero(key, sizeof(key));
	}
	guard(EVP_DigestFinal_ex(h, digest, &len) == 1 && len == DIGEST_LEN,
	    "hashing");
	EVP_MD_CTX_free(h);
}

static void
init_group(struct zkcmp *z)
{
	z->ctx = BN_CTX_new();
	z->g = BN_new();
	z->p = BN_get_rfc3526_prime_3072(NULL);
	z->q = BN_dup(z->p);
	guard(z->ctx && z->g && z->p && z->q && BN_sub_word(z->q, 1) == 1 &&
	    BN_rshift1(z->q, z->q) == 1 && BN_set_word(z->g, 2) == 1,
	    "group setup");
}

static void
gen_commit(struct zkcmp *z, const char *file, const char *s_file,
    const char *o_file)
{
	unsigned char digest[DIGEST_LEN], commitment[GROUP_LEN];
	FILE *fp;

	init_group(z);
	derive_digest(z, file, s_file, 1, digest);
	fp = create_file(o_file);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	guard(commit(z, digest, commitment) == 0, "commitment generation");
	explicit_bzero(digest, sizeof(digest));
	write_file(fp, o_file, commitment, sizeof(commitment));
}

static void
gen_proof(struct zkcmp *z, const char *file, const char *s_file,
    const char *o_file, uint64_t valid_secs)
{
	unsigned char digest[DIGEST_LEN], commitment[GROUP_LEN];
	unsigned char proof[PROOF_LEN];
	FILE *fp;

	init_group(z);
	derive_digest(z, file, s_file, 0, digest);
	fp = create_file(o_file);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	z->window = valid_secs ? window_of(time(NULL), valid_secs) : 0;
	guard(commit(z, digest, commitment) == 0, "commitment generation");
	guard(prove(z, digest, commitment, proof) == 0, "proof generation");
	explicit_bzero(digest, sizeof(digest));
	write_file(fp, o_file, proof, sizeof(proof));
}

static int
verify_proof(struct zkcmp *z, const char *c_file, const char *p_file,
    uint64_t valid_secs, int quiet)
{
	unsigned char commitment[GROUP_LEN], proof[PROOF_LEN];
	int status;

	if (read_file(c_file, commitment, GROUP_LEN) != GROUP_LEN)
		errx(ERR_EXIT, "invalid commitment size: %s", c_file);
	if (read_file(p_file, proof, PROOF_LEN) != PROOF_LEN)
		errx(ERR_EXIT, "invalid proof size: %s", p_file);

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	init_group(z);
	z->window = valid_secs ? window_of(time(NULL), valid_secs) : 0;
	status = verify(z, commitment, proof);
	if (status != OK_EXIT && z->window > 1) {
		z->window--;
		status = verify(z, commitment, proof);
	}
	if (status != OK_EXIT && !quiet)
		warnx("commitment and proof mismatched, or proof expired");
	return status;
}

static int
gen_salt(const char *file)
{
	unsigned char buf[DIGEST_LEN];
	FILE *fp = create_file(file);

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	arc4random_buf(buf, sizeof(buf));
	write_file(fp, file, buf, sizeof(buf));
	explicit_bzero(buf, sizeof(buf));
	return OK_EXIT;
}

int
main(int argc, char **argv)
{
	struct zkcmp z = { .h = EVP_sha256() };
	const char *file = NULL, *s_file = NULL, *o_file = NULL;
	uint64_t t = 0;
	int ch, cmd = 0, quiet = 0;

#ifdef __OpenBSD__
	if (pledge("stdio rpath wpath cpath tty", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "c:p:g:h:s:o:qCPt:")) != -1) {
		switch (ch) {
		case 'c':
		case 'p':
		case 'g':
			file = optarg;
			/* FALLTHROUGH */
		case 'C':
		case 'P':
			if (cmd)
				usage();
			cmd = ch;
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
			if (s_file)
				usage();
			s_file = optarg;
			break;
		case 'o':
			if (o_file)
				usage();
			o_file = optarg;
			break;
		case 't':
			if (t)
				usage();
			t = parse_u64(optarg);
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	switch (argc) {
	case 0:
		switch (cmd) {
		case 'c':
		case 'C':
			if (o_file && t == 0) {
				gen_commit(&z, file, s_file, o_file);
				return OK_EXIT;
			}
			break;
		case 'p':
		case 'P':
			if (o_file) {
				gen_proof(&z, file, s_file, o_file, t);
				return OK_EXIT;
			}
			break;
		case 'g':
			if (t == 0)
				return gen_salt(file);
			break;
		}
		break;
	case 2:
		switch (cmd) {
		case 0:
			return verify_proof(&z, argv[0], argv[1], t, quiet);
		}
		break;
	}
	usage();
}
