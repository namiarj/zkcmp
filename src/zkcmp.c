#include <err.h>
#include <fcntl.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr, "usage: zkcmp [-h hash] [-s psk] -c file -o commit\n"
			"       zkcmp [-h hash] [-s psk] -p file -o proof\n"
			"       zkcmp [-h hash] [-s psk] -C -o commit\n"
			"       zkcmp [-h hash] [-s psk] -P -o proof\n"
			"       zkcmp -g psk\n"
			"       zkcmp [-q] [-h hash] commit proof\n");
	exit(ERR_EXIT);
}
 
static void
require(int ok, const char *what)
{
	if (!ok)
		errx(ERR_EXIT, "%s failed", what);
}
 
static FILE *
create_file(const char *file, int excl)
{
	FILE *fp;
	int fd;
 
	fd = open(file, O_WRONLY | O_CREAT | (excl ? O_EXCL : O_TRUNC),
	    excl ? 0600 : 0666);
	if (fd == -1 || (fp = fdopen(fd, "wb")) == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	return fp;
}
 
static void
write_file(FILE *fp, const char *file, const void *buf, size_t len)
{
	if (fwrite(buf, 1, len, fp) != len || fclose(fp))
		err(ERR_EXIT, "failed to write %s", file);
}
 
static void
read_file(const char *file, void *buf, size_t len)
{
	FILE *fp;
 
	if ((fp = fopen(file, "rb")) == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	if (fread(buf, 1, len, fp) != len || fgetc(fp) != EOF || ferror(fp))
		errx(ERR_EXIT, "invalid file size or read error: %s", file);
	fclose(fp);
}
 
static void
read_password(unsigned char key[PW_KEY_LEN], const char *s_file, int confirm)
{
	unsigned char salt[GEN_PSK_LEN];
	char pw[PW_MAX], pw2[PW_MAX];
 
	if (s_file)
		read_file(s_file, salt, sizeof(salt));
	require(readpassphrase("Password: ", pw, sizeof(pw), RPP_ECHO_OFF) &&
	    *pw, "password input");
	require(!confirm || (readpassphrase("Confirm password: ", pw2,
	    sizeof(pw2), RPP_ECHO_OFF) && !strcmp(pw, pw2)),
	    "password confirmation");
	require(PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt,
	    s_file ? sizeof(salt) : 0, PW_ITER, EVP_sha512(), PW_KEY_LEN, key),
	    "key derivation");
	explicit_bzero(pw, sizeof(pw));
	explicit_bzero(pw2, sizeof(pw2));
}
 
static void
hash_file(EVP_MD_CTX *h, const char *file)
{
	unsigned char buf[IO_BUF_LEN];
	FILE *fp;
	size_t len;
 
	if ((fp = fopen(file, "rb")) == NULL)
		err(ERR_EXIT, "failed to open %s", file);
	while ((len = fread(buf, 1, sizeof(buf), fp)) != 0)
		require(EVP_DigestUpdate(h, buf, len), "hashing");
	if (ferror(fp))
		errx(ERR_EXIT, "read error: %s", file);
	explicit_bzero(buf, sizeof(buf));
	fclose(fp);
}
 
static void
derive_digest(const struct zkcmp *z, const char *file, const char *s_file,
	int confirm, unsigned char digest[DIGEST_LEN])
{
	unsigned char key[PW_KEY_LEN];
	EVP_MD_CTX *h = EVP_MD_CTX_new();
	unsigned int digest_len;
 
	require(h && EVP_DigestInit_ex(h, z->h, NULL) &&
	    EVP_DigestUpdate(h, DOMAIN_SEPARATOR, sizeof(DOMAIN_SEPARATOR)),
	    "hashing");
	if (file) {
		if (s_file)
			hash_file(h, s_file);
		hash_file(h, file);
	} else {
		read_password(key, s_file, confirm);
		require(EVP_DigestUpdate(h, key, sizeof(key)), "hashing");
		explicit_bzero(key, sizeof(key));
	}
	require(EVP_DigestFinal_ex(h, digest, &digest_len) &&
	    digest_len == DIGEST_LEN, "hashing");
	EVP_MD_CTX_free(h);
}
 
static void
init_group(struct zkcmp *z)
{
	z->ctx = BN_CTX_new();
	z->g = BN_new();
	z->p = BN_bin2bn(prime, sizeof(prime), NULL);
	z->q = BN_dup(z->p);
	require(z->ctx && z->g && z->p && z->q && BN_sub_word(z->q, 1) &&
	    BN_rshift1(z->q, z->q) && BN_set_word(z->g, 2), "group setup");
}
 
static int
gen_commit(struct zkcmp *z, const char *file, const char *o_file,
	const char *s_file)
{
	unsigned char digest[DIGEST_LEN], commitment[GROUP_LEN];
	FILE *fp;
 
	init_group(z);
	derive_digest(z, file, s_file, 1, digest);
	fp = create_file(o_file, 0);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	require(commit(z, digest, commitment) == 0, "commitment generation");
	explicit_bzero(digest, sizeof(digest));
	write_file(fp, o_file, commitment, sizeof(commitment));
	return OK_EXIT;
}
 
static int
gen_proof(struct zkcmp *z, const char *file, const char *o_file,
	const char *s_file)
{
	unsigned char digest[DIGEST_LEN], commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];
	FILE *fp;
 
	init_group(z);
	derive_digest(z, file, s_file, 0, digest);
	fp = create_file(o_file, 0);
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	require(commit(z, digest, commitment) == 0, "commitment generation");
	require(prove(z, digest, commitment, proof) == 0, "proof generation");
	explicit_bzero(digest, sizeof(digest));
	write_file(fp, o_file, proof, sizeof(proof));
	return OK_EXIT;
}
 
static int
verify_proof(struct zkcmp *z, const char *c_file, const char *p_file, int quiet)
{
	unsigned char commitment[GROUP_LEN], proof[GROUP_LEN * 2];
	int status;
 
	read_file(c_file, commitment, sizeof(commitment));
	read_file(p_file, proof, sizeof(proof));
#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	init_group(z);
	status = verify(z, commitment, proof);
	if (status == DIFF_EXIT && !quiet)
		warnx("commitment and proof mismatched");
	return status;
}
 
static int
gen_psk(const char *file)
{
	unsigned char buf[GEN_PSK_LEN];
	FILE *fp = create_file(file, 1);
 
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
	int ch, cmd = 0, quiet = 0;
 
#ifdef __OpenBSD__
	if (pledge("stdio rpath wpath cpath tty", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "c:p:g:h:s:o:qCP")) != -1) {
		switch (ch) {
		case 'c':
		case 'p':
		case 'g':
			file = optarg;
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
		case 'C':
			if (o_file)
				return gen_commit(&z, file, o_file, s_file);
			break;
		case 'p':
		case 'P':
			if (o_file)
				return gen_proof(&z, file, o_file, s_file);
			break;
		case 'g':
			return gen_psk(file);
		}
		break;
	case 2:
		switch (cmd) {
		case 0:
			argv += optind;
			return verify_proof(&z, argv[0], argv[1], quiet);
		}
	}
	usage();
}
