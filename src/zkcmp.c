#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr,
		"usage: zkcmp [-H hash] -c file\n"
		"       zkcmp [-H hash] -p file\n"
		"       zkcmp [-s] [-H hash] commit proof\n");
	exit(ERR_EXIT);
}

int
main(int argc, char **argv)
{
	struct zkcmp z = { .md = EVP_sha256() };
	int ch;

#ifdef __OpenBSD__
	if (pledge("stdio rpath", NULL) == -1)
		err(ERR_EXIT, "pledge");
#endif
	while ((ch = getopt(argc, argv, "sH:c:p:")) != -1) {
		switch (ch) {
		case 's':
			z.silent = 1;
			break;
		case 'H':
			if (strcmp(optarg, "sha512-256") == 0)
				z.md = EVP_sha512_256();
			else if (strcmp(optarg, "sha3-256") == 0)
				z.md = EVP_sha3_256();
			else if (strcmp(optarg, "sha256") != 0)
				usage();
			break;
		case 'c':
			return (cmd_commit(&z, optarg));
		case 'p':
			return (cmd_prove(&z, optarg));
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 2)
		return (cmd_verify(&z, argv[0], argv[1]));
	usage();
}
