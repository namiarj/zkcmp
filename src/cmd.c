#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "zkcmp.h"

int
cmd_commit(struct zkcmp *z, char *path)
{
    unsigned char digest[DIGEST_LEN];
    unsigned char commitment[GROUP_LEN];
    char encoded[B64_LEN];
    int n;

    setup_group(z);

    if (hash_path(path, digest, z) != 0)
        err(ERR_EXIT, "failed to hash %s", path);

    if (commit(z, digest, commitment) != 0)
        errx(ERR_EXIT, "commitment generation failed");

    free_group(z);

    n = EVP_EncodeBlock((unsigned char *)encoded,
        commitment, sizeof(commitment));
    if (n < 0)
        errx(ERR_EXIT, "base64 encoding failed");

    puts(encoded);
    return OK_EXIT;
}

int
cmd_prove(struct zkcmp *z, char *path)
{
    unsigned char digest[DIGEST_LEN];
    unsigned char commitment[GROUP_LEN];
    unsigned char proof[GROUP_LEN * 2];
    char encoded[B64_LEN];
    int n;

    setup_group(z);

    if (hash_path(path, digest, z) != 0)
        err(ERR_EXIT, "failed to hash %s", path);

    if (commit(z, digest, commitment) != 0)
        errx(ERR_EXIT, "commitment generation failed");

    if (prove(z, digest, commitment, proof) != 0)
        errx(ERR_EXIT, "proof generation failed");

    free_group(z);

    n = EVP_EncodeBlock((unsigned char *)encoded,
        proof, sizeof(proof));
    if (n < 0)
        errx(ERR_EXIT, "base64 encoding failed");

    puts(encoded);
    return OK_EXIT;
}

int
cmd_verify(struct zkcmp *z, char *commit_path, char *proof_path)
{
    unsigned char commitment[GROUP_LEN];
    unsigned char proof[GROUP_LEN * 2];
    char commitment_buf[B64_LEN];
    char proof_buf[B64_LEN];
    FILE *fp;
    int n;
    int status;

    fp = fopen(commit_path, "r");
    if (fp == NULL)
        err(ERR_EXIT, "failed to open %s", commit_path);

    if (fgets(commitment_buf, sizeof(commitment_buf), fp) == NULL) {
        fclose(fp);
        errx(ERR_EXIT, "failed to read %s", commit_path);
    }

    fclose(fp);

    fp = fopen(proof_path, "r");
    if (fp == NULL)
        err(ERR_EXIT, "failed to open %s", proof_path);

    if (fgets(proof_buf, sizeof(proof_buf), fp) == NULL) {
        fclose(fp);
        errx(ERR_EXIT, "failed to read %s", proof_path);
    }

    fclose(fp);

    setup_group(z);

    n = EVP_DecodeBlock(commitment,
        (unsigned char *)commitment_buf,
        (int)strlen(commitment_buf));
    if (n != GROUP_LEN)
        errx(ERR_EXIT, "invalid commitment");

    n = EVP_DecodeBlock(proof,
        (unsigned char *)proof_buf,
        (int)strlen(proof_buf));
    if (n != GROUP_LEN * 2)
        errx(ERR_EXIT, "invalid proof");

    status = verify(z, commitment, proof) ? OK_EXIT : DIFF_EXIT;

    if (status == DIFF_EXIT && !z->silent)
        warnx("commitment and proof mismatched");

    free_group(z);

    return status;
}
