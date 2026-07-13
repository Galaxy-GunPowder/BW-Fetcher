#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <brotli/decode.h>
#include <vector>

int brotli_decompress_cb(
    SSL* /*ssl*/,
    CRYPTO_BUFFER** out,
    size_t uncompressed_len,
    const uint8_t* in,
    size_t in_len
);
