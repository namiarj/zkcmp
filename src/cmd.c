#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zkcmp.h"

static int
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

/*
 * zkcmp commit file
 */
int
cmd_commit(struct zkcmp *z, int argc, char **argv)
{
	unsigned char digest[DIGEST_LEN];
	unsigned char commitment[GROUP_LEN];
	char *encoded;

	if (argc != 1)
		usage();

	setup_group(z);
	if (hash_path(argv[0], digest, z) != 0)
		err(ERR_EXIT, "failed to hash %s", argv[0]);
	if (commit(z, digest, commitment) != 0)
		errx(ERR_EXIT, "commitment generation failed");
	free_group(z);

	encoded = b64_encode(commitment, sizeof(commitment));
	if (encoded == NULL)
		errx(ERR_EXIT, "base64 encoding failed");
	puts(encoded);
	free(encoded);

	return OK_EXIT;
}

/*
 * zkcmp prove file
 */
int
cmd_prove(struct zkcmp *z, int argc, char **argv)
{
	unsigned char digest[DIGEST_LEN];
	unsigned char commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];
	char *encoded;

	if (argc != 1)
		usage();

	setup_group(z);
	if (hash_path(argv[0], digest, z) != 0)
		err(ERR_EXIT, "%s", argv[0]);
	if (commit(z, digest, commitment) != 0)
		errx(ERR_EXIT, "commitment generation failed");
	if (prove(z, digest, commitment, proof) != 0)
		errx(ERR_EXIT, "proof generation failed");
	free_group(z);

	encoded = b64_encode(proof, sizeof(proof));
	if (encoded == NULL)
		errx(ERR_EXIT, "base64 encoding failed");
	puts(encoded);
	free(encoded);

	return OK_EXIT;
}

/*
 * zkcmp verify commitment proof
 */
int
cmd_verify(struct zkcmp *z, int argc, char **argv)
{
	unsigned char commitment[GROUP_LEN];
	unsigned char proof[GROUP_LEN * 2];
	char commitment_buf[B64_LEN];
	char proof_buf[B64_LEN];
	int status;

	if (argc != 2)
		usage();

	setup_group(z);

	load_param(argv[0], commitment_buf, sizeof(commitment_buf));
	if (b64_decode(commitment_buf, commitment,
	    sizeof(commitment)) != GROUP_LEN)
		errx(ERR_EXIT, "invalid commitment");

	load_param(argv[1], proof_buf, sizeof(proof_buf));
	if (b64_decode(proof_buf, proof, sizeof(proof)) != GROUP_LEN * 2)
		errx(ERR_EXIT, "invalid proof");

	status = verify(z, commitment, proof) ? OK_EXIT : DIFF_EXIT;
	free_group(z);

	if (status == DIFF_EXIT && !z->silent)
		warnx("commitment and proof mismatched");

	return status;
}
