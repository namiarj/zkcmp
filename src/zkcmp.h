#define OK_EXIT     0
#define DIFF_EXIT   1
#define ERR_EXIT    2

/* RFC 3526 / 3072-bit MODP group size. */
#define GROUP_LEN   384
#define DIGEST_LEN  32
#define COMMIT_LEN  (GROUP_LEN)
#define PROOF_LEN   (GROUP_LEN + GROUP_LEN)
#define IO_BUF_LEN  16384
#define B64_LEN     8192

struct zkcmp {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BN_CTX *ctx;
    const EVP_MD *md;
    int silent;
    int nofollow;
};

static const char *prime_hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

void usage(void);
void setup_group(struct zkcmp*);
void free_group(struct zkcmp*);
int bn_fixed(const BIGNUM*, unsigned char*, size_t);
char *b64_encode(const unsigned char*, size_t);
int b64_decode(const char*, unsigned char*, size_t);
int load_param(const char*, char*, size_t);
int hash_stream(FILE*, unsigned char digest[DIGEST_LEN], struct zkcmp*);
int hash_path(const char*, unsigned char digest[DIGEST_LEN], struct zkcmp*);
int gen_commit(struct zkcmp*, const unsigned char digest[DIGEST_LEN], unsigned char commit[COMMIT_LEN]);
int gen_proof(struct zkcmp*, const unsigned char digest[DIGEST_LEN], const unsigned char commit[COMMIT_LEN], unsigned char proof[PROOF_LEN]);
int verify(struct zkcmp*, const unsigned char commit[COMMIT_LEN], const unsigned char proof[PROOF_LEN]);
int cmd_commit(struct zkcmp*, int, char**);
int cmd_prove(struct zkcmp*, int, char**);
int cmd_verify(struct zkcmp*, int, char**);
int cmd_check(struct zkcmp*, int, char**);
