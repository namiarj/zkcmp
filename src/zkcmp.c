#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zkcmp.h"

static void
usage(void)
{
	fprintf(stderr,
		"usage: zkcmp [-H hash] commit file\n"
		"       zkcmp [-H hash] prove file\n"
		"       zkcmp [-s] [-H hash] verify commit proof\n");
	exit(ERR_EXIT);
}

int
main(int argc, char **argv)
{
	struct zkcmp z = {.md = EVP_sha256()};
	char *cmd;
	int ch;

#ifdef __OpenBSD__
	pledge("stdio rpath", NULL);
#endif

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "sH:")) != -1) {
		switch (ch) {
		case 's':
			z.silent = 1;
			break;
		case 'H':
			switch (optarg[3]) {
			case '2':
				if (strcmp(optarg, "sha256"))
					usage();
				break;
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
			case '?':
			default:
				usage();
			}
		}
	}

	argc -= optind;
	argv += optind;
	cmd = argv[0];

	switch (cmd[0]) {
	case 'c':
		if (strcmp(cmd, "commit") || argc != 1)
			usage();
		return cmd_commit(&z, argv[0]);
	case 'p':
		if (strcmp(cmd, "prove") || argc != 1)
			usage();
		return cmd_prove(&z, argv[0]);
	case 'v':
		if (strcmp(cmd, "verify") || argc != 2)
			usage();
		return cmd_verify(&z, argv[0], argv[1]);
	default:
		usage();
	}
}
