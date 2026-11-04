#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <bsd/readpassphrase.h>
#include <bsd/stdlib.h>
#else
#include <readpassphrase.h>
#include <stdlib.h>
#endif

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr, "usage: zkcmp -c [-h hash] [-s salt] file commit\n"
		"       zkcmp -p [-h hash] [-s salt] [-t seconds] file proof\n"
		"       zkcmp -C [-h hash] [-s salt] commit\n"
		"       zkcmp -P [-h hash] [-s salt] [-t seconds] proof\n"
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

static FILE *
create_file(const char *o)
{
	int fd = open(o, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	FILE *f = (fd == -1) ? NULL : fdopen(fd, "wb");

	if (f == NULL)
		err(ERR_EXIT, "failed to open %s", o);
	return f;
}

static size_t
read_file(const char *path, void *buf, size_t cap)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (f == NULL)
		err(ERR_EXIT, "failed to open %s", path);
	n = fread(buf, 1, cap, f);
	if (ferror(f) || fgetc(f) != EOF)
		errx(ERR_EXIT, "invalid file size or read error: %s", path);
	fclose(f);
	return n;
}

static void
read_password(unsigned char key[DIGEST_LEN], const char *s, int confirm)
{
	unsigned char salt[DIGEST_LEN] = { 0 };
	char pw[PW_MAX], pw2[PW_MAX];

	if (s && read_file(s, salt, sizeof(salt)) != sizeof(salt))
		errx(ERR_EXIT, "invalid salt size: %s", s);
	guard(readpassphrase("Password: ", pw, sizeof(pw), RPP_ECHO_OFF) &&
	    *pw, "password input");
	guard(!confirm || (readpassphrase("Confirm password: ", pw2,
	    sizeof(pw2), RPP_ECHO_OFF) && strcmp(pw, pw2) == 0),
	    "password confirmation");
	guard(PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt,
	    s ? sizeof(salt) : 0, PW_ITER, EVP_sha512(), DIGEST_LEN, key),
	    "key derivation");
	explicit_bzero(pw, sizeof(pw));
	explicit_bzero(pw2, sizeof(pw2));
}

static void
hash_file(EVP_MD_CTX *h, const char *path)
{
	unsigned char buf[IO_BUF_LEN];
	FILE *f = fopen(path, "rb");
	size_t n;

	if (f == NULL)
		err(ERR_EXIT, "failed to open %s", path);
	while ((n = fread(buf, 1, sizeof(buf), f)) != 0)
		guard(EVP_DigestUpdate(h, buf, n) == 1, "hashing");
	if (ferror(f))
		errx(ERR_EXIT, "read error: %s", path);
	explicit_bzero(buf, sizeof(buf));
	fclose(f);
}

static void
derive_digest(const struct zkcmp *z, const char *path, const char *s,
    int confirm, unsigned char digest[DIGEST_LEN])
{
	unsigned char key[DIGEST_LEN];
	EVP_MD_CTX *h = EVP_MD_CTX_new();
	unsigned int len = 0;

	guard(h && EVP_DigestInit_ex(h, z->h, NULL) == 1 &&
	    EVP_DigestUpdate(h, DOMAIN_SEPARATOR, sizeof(DOMAIN_SEPARATOR)) == 1,
	    "hashing");
	if (path) {
		if (s)
			hash_file(h, s);
		hash_file(h, path);
	} else {
		read_password(key, s, confirm);
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

static int
gen_commit(struct zkcmp *z, const char *s, const char *path,
    const char *o)
{
	unsigned char digest[DIGEST_LEN], commitment[COMMIT_LEN];
	FILE *f;

	init_group(z);
	derive_digest(z, path, s, 1, digest);
	f = create_file(o);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	guard(commit(z, digest, commitment) == 0, "commitment generation");
	explicit_bzero(digest, sizeof(digest));
	if (fwrite(commitment, 1, sizeof(commitment), f) != sizeof(commitment) || fclose(f))
		err(ERR_EXIT, "failed to write %s", o);
	return OK_EXIT;
}

static int
gen_proof(struct zkcmp *z, const char *s, uint64_t t, const char *path,
    const char *o)
{
	unsigned char digest[DIGEST_LEN], commitment[COMMIT_LEN];
	unsigned char proof[PROOF_LEN];
	FILE *f;

	init_group(z);
	derive_digest(z, path, s, 0, digest);
	f = create_file(o);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	z->window = t ? (uint64_t)time(NULL) / t + 1 : 0;
	guard(commit(z, digest, commitment) == 0, "commitment generation");
	guard(prove(z, digest, commitment, proof) == 0, "proof generation");
	explicit_bzero(digest, sizeof(digest));
	if (fwrite(proof, 1, sizeof(proof), f) != sizeof(proof) || fclose(f))
		err(ERR_EXIT, "failed to write %s", o);
	return OK_EXIT;
}

static int
verify_proof(struct zkcmp *z, int q, uint64_t t, const char *c, const char *p)
{
	unsigned char commitment[COMMIT_LEN], proof[PROOF_LEN];
	int status;

	if (read_file(c, commitment, COMMIT_LEN) != COMMIT_LEN)
		errx(ERR_EXIT, "invalid commitment size: %s", c);
	if (read_file(p, proof, PROOF_LEN) != PROOF_LEN)
		errx(ERR_EXIT, "invalid proof size: %s", p);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	init_group(z);
	z->window = t ? (uint64_t)time(NULL) / t + 1 : 0;
	status = verify(z, commitment, proof);
	if (status != OK_EXIT && z->window > 1) {
		z->window--;
		status = verify(z, commitment, proof);
	}
	if (status != OK_EXIT && !q) {
		if (t)
			warnx("commitment and proof mismatched, or proof expired");
		else
			warnx("commitment and proof mismatched");
	}
	return status;
}

static int
gen_salt(const char *o)
{
	unsigned char buf[DIGEST_LEN];
	FILE *f = create_file(o);

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	arc4random_buf(buf, sizeof(buf));
	if (fwrite(buf, 1, sizeof(buf), f) != sizeof(buf) || fclose(f))
		err(ERR_EXIT, "failed to write %s", o);
	explicit_bzero(buf, sizeof(buf));
	return OK_EXIT;
}

int
main(int argc, char **argv)
{
	struct zkcmp z = { .h = EVP_sha256() };
	const char *s = NULL;
	char *p;
	uint64_t t = 0;
	int ch, cmd = 0, q = 0;

#ifdef __OpenBSD__
	if (pledge("stdio rpath wpath cpath tty", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "gcpCPh:s:t:q")) != -1) {
		switch (ch) {
		case 'c':
		case 'p':
		case 'g':
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
			if (s)
				usage();
			s = optarg;
			break;
		case 't':
			if (t)
				usage();
			t = strtoull(optarg, &p, 10);
			if (errno || *p)
					usage();
			break;
		case 'q':
			q = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	switch (argc) {
	case 1:
		switch (cmd) {
		case 'g':
			if (!t)
				return gen_salt(argv[0]);
			break;
		case 'C':
			if (!t)
				return gen_commit(&z, s, NULL, argv[0]);
			break;
		case 'P':
			return gen_proof(&z, s, t, NULL, argv[0]);
		}
		break;
	case 2:
		switch (cmd) {
		case 'c':
			if (!t)
				return gen_commit(&z, s, argv[0], argv[1]);
			break;
		case 'p':
			return gen_proof(&z, s, t, argv[0], argv[1]);
		case 0:
			return verify_proof(&z, q, t, argv[0], argv[1]);
		}
	}
	usage();
}
