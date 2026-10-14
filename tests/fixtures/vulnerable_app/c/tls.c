#include <openssl/ssl.h>
#include <openssl/rsa.h>

void setup(SSL_CTX *ctx) {
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256");
    RSA *r = RSA_new();
    RSA_generate_key_ex(r, 2048, NULL, NULL);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
}

void modern(SSL_CTX *ctx) {
    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519");
}
