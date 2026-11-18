#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <bsd/readpassphrase.h>
#include <bsd/stdlib.h>
#include <sys/prctl.h>
#else
#include <readpassphrase.h>
#endif

#if defined(__OpenBSD__)
#include <libgen.h>
#endif

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr, "usage: zkcmp -c [-b] [-h hash] [-s salt] file commit\n"
		"       zkcmp -p [-b] [-h hash] [-s salt] [-t seconds] [-x context] file proof\n"
		"       zkcmp -C [-b] [-h hash] [-s salt] commit\n"
		"       zkcmp -P [-b] [-h hash] [-s salt] [-t seconds] [-x context] proof\n"
		"       zkcmp -g salt\n"
		"       zkcmp [-q] [-h hash] [-t seconds] [-x context] commit proof\n");
	exit(ERR_EXIT);
}

static struct {
	char pw[PW_MAX], pw2[PW_MAX];
	unsigned char buf[IO_BUF_LEN], salt[DIGEST_LEN], pre[DIGEST_LEN];
	unsigned char digest[DIGEST_LEN];
} sec;

static void
wipe(void)
{
	explicit_bzero(&sec, sizeof(sec));
}

static void
onsig(int sig)
{
	wipe();
	signal(sig, SIG_DFL);
	raise(sig);
}

static void
guard(int ok, const char *what)
{
	if (!ok)
		errx(ERR_EXIT, "%s failed", what);
}

static void
write_file(const char *o, const void *buf, size_t len)
{
	int fd = strcmp(o, "-") ? open(o, O_WRONLY | O_CREAT | O_TRUNC, 0600)
	    : STDOUT_FILENO;
	FILE *f = (fd == -1) ? NULL : fdopen(fd, "wb");
	size_t n;

	if (f == NULL)
		err(ERR_EXIT, "failed to open %s", o);
	n = fwrite(buf, 1, len, f);
	if (fclose(f) != 0 || n != len)
		err(ERR_EXIT, "failed to write %s", o);
}

static size_t
read_file(const char *path, void *buf, size_t cap)
{
	FILE *f = fopen(path, "rb");
	size_t n;
	int bad;

	if (f == NULL)
		err(ERR_EXIT, "failed to open %s", path);
	n = fread(buf, 1, cap, f);
	bad = ferror(f) || fgetc(f) != EOF;
	fclose(f);
	if (bad)
		errx(ERR_EXIT, "invalid file size or read error: %s", path);
	return n;
}

static void
load(const char *path, unsigned char *out, size_t len)
{
	unsigned char buf[B64_LEN(PROOF_LEN) + 2];
	size_t n = read_file(path, buf, sizeof(buf));

	if (n == len) {
		memcpy(out, buf, len);
		return;
	}
	if (n == B64_LEN(len) + 1 && buf[n - 1] == '\n')
		n--;
	if (n != B64_LEN(len) || EVP_DecodeBlock(out, buf, n) != (int)len)
		errx(ERR_EXIT, "invalid size or encoding: %s", path);
}

static void
save(const char *o, const unsigned char *buf, size_t len, int b64)
{
	unsigned char enc[B64_LEN(PROOF_LEN) + 2];
	int n;

	if (!b64) {
		write_file(o, buf, len);
		return;
	}
	n = EVP_EncodeBlock(enc, buf, (int)len);
	enc[n++] = '\n';
	write_file(o, enc, (size_t)n);
}

static void
hash_file(EVP_MD_CTX *h, const char *path)
{
	FILE *f = fopen(path, "rb");
	size_t n = 0;
	int ok = 1, bad;

	if (f == NULL)
		err(ERR_EXIT, "failed to open %s", path);
	while (ok && (n = fread(sec.buf, 1, sizeof(sec.buf), f)) != 0)
		ok = EVP_DigestUpdate(h, sec.buf, n) == 1;
	bad = ferror(f) || !ok;
	fclose(f);
	if (bad)
		errx(ERR_EXIT, "read or hashing error: %s", path);
}

static void
derive(const struct zkcmp *z, const char *path, int confirm)
{
	EVP_MD_CTX *h = EVP_MD_CTX_new();
	unsigned int len = 0;

	if (z->s && read_file(z->s, sec.salt, sizeof(sec.salt)) != sizeof(sec.salt))
		errx(ERR_EXIT, "invalid salt size: %s", z->s);
	guard(h && EVP_DigestInit_ex(h, z->h, NULL) == 1 &&
	    EVP_DigestUpdate(h, DOMAIN_SEPARATOR, sizeof(DOMAIN_SEPARATOR)) == 1,
	    "hashing");
	if (path) {
		hash_file(h, path);
	} else {
		guard(readpassphrase("Password: ", sec.pw, sizeof(sec.pw),
		    RPP_ECHO_OFF | RPP_REQUIRE_TTY) && *sec.pw,
		    "password input");
		guard(!confirm || (readpassphrase("Confirm password: ", sec.pw2,
		    sizeof(sec.pw2), RPP_ECHO_OFF | RPP_REQUIRE_TTY) &&
		    strcmp(sec.pw, sec.pw2) == 0), "password confirmation");
		guard(EVP_DigestUpdate(h, sec.pw, strlen(sec.pw)) == 1,
		    "hashing");
		explicit_bzero(sec.pw, sizeof(sec.pw));
		explicit_bzero(sec.pw2, sizeof(sec.pw2));
	}
	guard(EVP_DigestFinal_ex(h, sec.pre, &len) == 1 && len == DIGEST_LEN,
	    "hashing");
	EVP_MD_CTX_free(h);
	guard(PKCS5_PBKDF2_HMAC((const char *)sec.pre, DIGEST_LEN, sec.salt,
	    z->s ? DIGEST_LEN : 0, PBKDF2_ITER, EVP_sha512(), DIGEST_LEN,
	    sec.digest), "key derivation");
	explicit_bzero(sec.pre, sizeof(sec.pre));
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
gen_statement(struct zkcmp *z, char mode, const char *path, const char *o,
    int b64)
{
	unsigned char commitment[COMMIT_LEN], proof[PROOF_LEN];
	int is_proof = mode == 'p' || mode == 'P';

	init_group(z);
	derive(z, path, mode == 'c' || mode == 'C');
	guard(commit(z, sec.digest, commitment) == 0, "commitment generation");
	if (is_proof) {
		z->window = z->t ? (uint64_t)time(NULL) / z->t + 1 : 0;
		guard(prove(z, sec.digest, commitment, proof) == 0,
		    "proof generation");
		save(o, proof, PROOF_LEN, b64);
	} else {
		save(o, commitment, COMMIT_LEN, b64);
	}
	return OK_EXIT;
}

static int
verify_proof(struct zkcmp *z, int q, const char *c, const char *p)
{
	unsigned char commitment[COMMIT_LEN], proof[PROOF_LEN];
	int status;

	init_group(z);
	load(c, commitment, COMMIT_LEN);
	load(p, proof, PROOF_LEN);
	z->window = z->t ? (uint64_t)time(NULL) / z->t + 1 : 0;
	status = verify(z, commitment, proof);
	if (status != OK_EXIT && z->window > 1) {
		z->window--;
		status = verify(z, commitment, proof);
	}
	if (status != OK_EXIT && !q)
			warnx("commitment and proof mismatched");
	return status;
}

static int
gen_salt(const char *o)
{
	arc4random_buf(sec.salt, sizeof(sec.salt));
	write_file(o, sec.salt, sizeof(sec.salt));
	return OK_EXIT;
}

#if defined(__OpenBSD__)
static void
lock_files(const struct zkcmp *z, int cmd, int argc, char **argv)
{
	char *d;
	int i;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-") == 0)
			continue;
		if (cmd && i == argc - 1) {
			d = strdup(argv[i]);
			guard(d != NULL && unveil(dirname(d), "wc") == 0,
			    "unveil");
			free(d);
		} else {
			guard(unveil(argv[i], "r") == 0, "unveil");
		}
	}
	if (z->s)
		guard(unveil(z->s, "r") == 0, "unveil");
	if (cmd == 'C' || cmd == 'P')
		guard(unveil("/dev/tty", "rw") == 0, "unveil");
	guard(unveil(NULL, NULL) == 0, "unveil");
}
#endif

int
main(int argc, char **argv)
{
	struct zkcmp z = { 0 };
	struct rlimit rl = { 0, 0 };
	char *ptr;
	int ch, cmd = 0, q = 0, b = 0;

	guard(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit");
#if defined(__linux__)
	guard(prctl(PR_SET_DUMPABLE, 0) == 0, "prctl");
#endif
	guard(mlock(&sec, sizeof(sec)) == 0, "mlock");
	guard(atexit(wipe) == 0, "atexit");
	signal(SIGHUP, onsig);
	signal(SIGINT, onsig);
	signal(SIGQUIT, onsig);
	signal(SIGTERM, onsig);
#ifdef __OpenBSD__
	if (pledge("stdio rpath wpath cpath tty unveil", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "bgcpCPh:s:t:qx:")) != -1) {
		switch (ch) {
		case 'b':
			b = 1;
			break;
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
			if (z.h)
				usage();
			if (!strcmp(optarg, "sha512-256"))
				z.h = EVP_sha512_256();
			else if (!strcmp(optarg, "sha3-256"))
				z.h = EVP_sha3_256();
			else if (!strcmp(optarg, "sha256"))
				z.h = EVP_sha256();
			else
				usage();
			break;
		case 's':
			if (z.s)
				usage();
			z.s = optarg;
			break;
		case 't':
			if (z.t)
				usage();
			errno = 0;
			z.t = strtoull(optarg, &ptr, 10);
			if (errno || *ptr)
				usage();
			break;
		case 'x':
			if (z.x)
				usage();
			z.x = optarg;
			break;
		case 'q':
			q = 1;
			break;
		default:
			usage();
		}
	}
#if defined(__OpenBSD__)
	lock_files(&z, cmd, argc, argv);
#endif
	if (!z.h)
		z.h = EVP_sha256();
	argc -= optind;
	argv += optind;
	switch (argc) {
	case 1:
		switch (cmd) {
		case 'g':
			if (!z.s && !z.t && !z.x && !b)
				return gen_salt(argv[0]);
			break;
		case 'C':
			if (!z.t && !z.x)
				return gen_statement(&z, cmd, NULL, argv[0], b);
			break;
		case 'P':
			return gen_statement(&z, cmd, NULL, argv[0], b);
		}
		break;
	case 2:
		switch (cmd) {
		case 'c':
			if (!z.t && !z.x)
				return gen_statement(&z, cmd, argv[0], argv[1], b);
			break;
		case 'p':
			return gen_statement(&z, cmd, argv[0], argv[1], b);
		case 0:
			if (!z.s && !b)
				return verify_proof(&z, q, argv[0], argv[1]);
		}
		break;
	}
	usage();
}
