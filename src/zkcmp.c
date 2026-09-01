/*
 * zkcmp - zero-knowledge file comparison utility
 *
 * Zero-knowledge Schnorr protocol:
 *
 * Secret:
 *    x = hash(file) mod q
 *
 * Commit:
 *    Y = g^x mod p
 *
 * Proof:
 *    k <- random Zq
 *    R = g^k
 *    c = H(Y || R) mod q
 *    z = k + c*x mod q
 *
 * Verification:
 *    g^z == R * Y^c mod p
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "zkcmp.h"

void
usage(void)
{
    fprintf(stderr,
        "usage: zkcmp commit [-h] [-H sha256|sha3-256|blake2s-256] file\n"
        "       zkcmp prove [-h] [-H sha256|sha3-256|blake2s-256] file\n"
        "       zkcmp verify [-hs] [-H sha256|sha3-256|blake2s-256] commit proof\n"
        "       zkcmp check [-hs] [-H sha256|sha3-256|blake2s-256] file proof\n");
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
        if (fp == NULL) {
            if (strlen(arg) >= len)
                return (-1);
            strlcpy(buf, arg, len);
            return (0);
        }
    }
    if (fgets(buf, len, fp) == NULL) {
        if (fp != stdin)
            fclose(fp);
        return (-1);
    }
    if (fp != stdin)
        fclose(fp);
    n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n')
        buf[n - 1] = '\0';
    return (0);
}

/* 
 * Main
 */
int
main(int argc, char **argv)
{
    struct zkcmp z;
    const char *cmd;
    const char *optstr;
    int ch;

    if (argc < 2)
        usage();
    cmd = argv[1];
    if (strcmp(cmd, "commit") == 0 || strcmp(cmd, "prove") == 0)
        optstr = "hH:";
    else if (strcmp(cmd, "verify") == 0 || strcmp(cmd, "check") == 0)
        optstr = "hsH:";
    else
        usage();
    memset(&z, 0, sizeof(z));
    z.md = EVP_sha256();
    argc -= 1;
    argv += 1;
    optind = 1;
    while ((ch = getopt(argc, argv, optstr)) != -1) {
        switch (ch) {
        case 'h':
            z.nofollow = 1;
            break;
        case 'H':
            if (strcmp(optarg, "sha3-256") == 0)
                z.md = EVP_sha3_256();
            else if (strcmp(optarg, "blake2s-256") == 0)
                z.md = EVP_blake2s256();
            else if (strcmp(optarg, "sha256") != 0)
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
    if (strcmp(cmd, "commit") == 0)
        return (cmd_commit(&z, argc, argv));
    if (strcmp(cmd, "prove") == 0)
        return (cmd_prove(&z, argc, argv));
    if (strcmp(cmd, "verify") == 0)
        return (cmd_verify(&z, argc, argv));
    return (cmd_check(&z, argc, argv));
}
