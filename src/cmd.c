#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "zkcmp.h"

/*
 * zkcmp commit file
 */
int
cmd_commit(struct zkcmp *z, int argc, char **argv)
{
    unsigned char digest[DIGEST_LEN];
    unsigned char commit[COMMIT_LEN];
    char *encoded;

    if (argc != 1)
        usage();
    setup_group(z);
    if (hash_path(argv[0], digest, z) != 0)
        err(ERR_EXIT, "failed to hash %s", argv[0]);
    if (gen_commit(z, digest, commit) != 0)
        errx(ERR_EXIT, "commit generation failed");
    free_group(z);
    encoded = b64_encode(commit, sizeof(commit));
    if (encoded == NULL)
        errx(ERR_EXIT, "base64 encoding failed");
    puts(encoded);
    free(encoded);
    return (OK_EXIT);
}

/*
 * zkcmp prove file
 */
int
cmd_prove(struct zkcmp *z, int argc, char **argv)
{
    unsigned char digest[DIGEST_LEN];
    unsigned char commit[COMMIT_LEN];
    unsigned char proof[PROOF_LEN];
    char *encoded;

    if (argc != 1)
        usage();
    setup_group(z);
    if (hash_path(argv[0], digest, z) != 0)
        err(ERR_EXIT, "%s", argv[0]);
    if (gen_commit(z, digest, commit) != 0)
        errx(ERR_EXIT, "commit generation failed");
    if (gen_proof(z, digest, commit, proof) != 0)
        errx(ERR_EXIT, "proof generation failed");
    free_group(z);
    encoded = b64_encode(proof, sizeof(proof));
    if (encoded == NULL)
        errx(ERR_EXIT, "base64 encoding failed");
    puts(encoded);
    free(encoded);
    return (OK_EXIT);
}

/*
 * zkcmp verify commit proof
 */
int
cmd_verify(struct zkcmp *z, int argc, char **argv)
{
    unsigned char commit[COMMIT_LEN];
    unsigned char proof[PROOF_LEN];
    char commit_buf[B64_LEN];
    char proof_buf[B64_LEN];
    int status;

    if (argc != 2)
        usage();
    setup_group(z);
    load_param(argv[0], commit_buf, sizeof(commit_buf));
    if (b64_decode(commit_buf, commit, sizeof(commit)) != COMMIT_LEN)
        errx(ERR_EXIT, "invalid commit");
    load_param(argv[1], proof_buf, sizeof(proof_buf));
    if (b64_decode(proof_buf, proof, sizeof(proof)) != PROOF_LEN)
        errx(ERR_EXIT, "invalid proof");
    status = verify(z, commit, proof) ? OK_EXIT : DIFF_EXIT;
    free_group(z);
    if (status == DIFF_EXIT && !z->silent)
        warnx("commit and proof mismatched");
    return (status);
}

/*
 * zkcmp check file proof
 */
int
cmd_check(struct zkcmp *z, int argc, char **argv)
{
    unsigned char digest[DIGEST_LEN];
    unsigned char commit[COMMIT_LEN];
    unsigned char proof[PROOF_LEN];
    char proof_buf[B64_LEN];
    int status;

    if (argc != 2)
        usage();
    setup_group(z);
    if (hash_path(argv[0], digest, z) != 0)
        err(ERR_EXIT, "failed to hash %s", argv[0]);
    if (gen_commit(z, digest, commit) != 0)
        errx(ERR_EXIT, "commit generation failed");
    load_param(argv[1], proof_buf, sizeof(proof_buf));
    if (b64_decode(proof_buf, proof, sizeof(proof)) != PROOF_LEN)
        errx(ERR_EXIT, "invalid proof");
    status = verify(z, commit, proof) ? OK_EXIT : DIFF_EXIT;
    free_group(z);
    if (status == DIFF_EXIT && !z->silent)
        warnx("file and proof mismatched");
    return (status);
}
