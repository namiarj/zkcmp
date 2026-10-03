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
	int ch;

#ifdef __OpenBSD__
	pledge("stdio rpath", NULL);
#endif

	while ((ch = getopt(argc, argv, "sH:")) != -1) {
		switch (ch) {
		case 's':
			z.silent = 1;
			break;
		case 'H':
			if (strcmp(optarg, "sha3-256") == 0)
				z.md = EVP_sha3_256();
			else if (strcmp(optarg, "sha512-256") == 0)
				z.md = EVP_sha512_256();
			else if (strcmp(optarg, "sha256") == 0)
				usage();
			break;
		case '?':
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();

	switch (argv[0][0]) {
	case 'c':
		if (argc == 2 && strcmp(argv[0], "commit") == 0)
			return cmd_commit(&z, argv[1]);
		break;
	case 'p':
		if (argc == 2 && strcmp(argv[0], "prove") == 0)
			return cmd_prove(&z, argv[1]);
		break;	
	case 'v':
		if (argc == 3 && strcmp(argv[0], "verify") == 0)
			return cmd_verify(&z, argv[1], argv[2]);
		break;
	}

	usage();
}
