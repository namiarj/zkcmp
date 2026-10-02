#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "zkcmp.h"

void
usage(void)
{
	fprintf(stderr,
	    "usage: zkcmp commit [-h] [-H sha256|sha3-256|sha512-256] file\n"
	    "       zkcmp prove [-h] [-H sha256|sha3-256|sha512-256] file\n"
	    "       zkcmp verify [-hs] [-H sha256|sha3-256|sha512-256] commit proof\n");
	exit(ERR_EXIT);
}

int
load_param(const char *arg, char *buf, size_t len)
{
	FILE *fp;
	size_t n;

	if (strcmp(arg, "-") == 0)
		fp = stdin;
	else {
		fp = fopen(arg, "r");
		if (!fp) {
			if (strlcpy(buf, arg, len) >= len)
				return -1;
			return 0;
		}
	}

	if (!fgets(buf, len, fp)) {
		if (fp != stdin)
			fclose(fp);
		return -1;
	}

	if (fp != stdin)
		fclose(fp);

	n = strlen(buf);
	if (n > 0 && buf[n - 1] == '\n')
		buf[n - 1] = '\0';

	return 0;
}

int
main(int argc, char **argv)
{
	struct zkcmp z = { .md = EVP_sha256() };
	const char *cmd;
	int ch;

#ifdef __OpenBSD__
	pledge("stdio rpath", NULL);
#endif

	if (argc < 2)
		usage();

	cmd = argv[1];

	argc--;
	argv++;

	while ((ch = getopt(argc, argv, "hsH:")) != -1) {
		switch (ch) {
		case 'h':
			z.nofollow = 1;
			break;
		case 's':
			z.silent = 1;
			break;
		case 'H':
			if (strcmp(optarg, "sha3-256") == 0)
				z.md = EVP_sha3_256();
			else if (strcmp(optarg, "sha512-256") == 0)
				z.md = EVP_sha512_256();
			else if (strcmp(optarg, "sha256") != 0)
				usage();
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (strcmp(cmd, "commit") == 0)
		return cmd_commit(&z, argc, argv);
	if (strcmp(cmd, "prove") == 0)
		return cmd_prove(&z, argc, argv);
	if (strcmp(cmd, "verify") == 0)
		return cmd_verify(&z, argc, argv);

	usage();
}
