#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

_Noreturn static void
usage(void)
{
	fprintf(stderr,
		"usage: zkcmp [-h hash] -c file\n"
		"       zkcmp [-h hash] -p file\n"
		"       zkcmp [-s] [-h hash] commit proof\n");
	exit(ERR_EXIT);
}

int
main(int argc, char **argv)
{
	struct zkcmp z = { .md = EVP_sha256() };
	const char *file = NULL;
	int ch;
	char cmd = 0;

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
				z.md = EVP_sha512_256();
			else if (!strcmp(optarg, "sha3-256"))
				z.md = EVP_sha3_256();
			else if (strcmp(optarg, "sha256"))
				usage();
			break;
		case 's':
			z.silent = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	switch (argc) {
	case 0:
		switch(cmd) {
		case 'c':
			return (cmd_commit(&z, file));
		case 'p':
			return (cmd_prove(&z, file));
		}
		break;
	case 2:
		if (!cmd)
			return (cmd_verify(&z, argv[0], argv[1]));
	}
	usage();
}
