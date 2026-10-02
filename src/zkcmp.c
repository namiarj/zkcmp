#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
main(int argc, char **argv)
{
	struct zkcmp z = {.md = EVP_sha256()};
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
			switch (optarg[3]) {
			case '3':
				if (strcmp(optarg, "sha3-256"))
					usage();
				z.md = EVP_sha3_256();
				break;
			case '5':
				if (strcmp(optarg, "sha512-256"))
					usage();
				z.md = EVP_sha512_256();
				break;
			case '2':
				if (strcmp(optarg, "sha256"))
					usage();
				break;
			default:
				usage();
			}
		}
	}

	argc -= optind;
	argv += optind;

	switch (cmd[0]) {
	case 'c':
		if (strcmp(cmd, "commit"))
			usage();
		return cmd_commit(&z, argc, argv);
	case 'p':
		if (strcmp(cmd, "prove"))
			usage();
		return cmd_prove(&z, argc, argv);
	case 'v':
		if (strcmp(cmd, "verify"))
			usage();
		return cmd_verify(&z, argc, argv);
	default:
		usage();
	}
}
