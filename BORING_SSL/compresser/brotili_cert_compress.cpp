#include <openssl/ssl.h>
#include <brotli/decode.h>
#include <vector>
#include <cstring>

#define MAX_CERT_SIZE (16 * 1024 * 1024) // 16MB hard cap
int brotli_decompress_cb(
    SSL* /*ssl*/,
    CRYPTO_BUFFER** out,
    size_t uncompressed_len,
    const uint8_t* in,
    size_t in_len
) {
    if (uncompressed_len > (16 * 1024 * 1024)) {
        return 0; // hard safety cap
    }

    std::vector<uint8_t> buffer;
    buffer.resize(uncompressed_len);

    BrotliDecoderResult res = BrotliDecoderDecompress(
        in_len,
        in,
        &uncompressed_len,
        buffer.data()
    );

    if (res != BROTLI_DECODER_RESULT_SUCCESS) {
        return 0;
    }

    CRYPTO_BUFFER* cb =
        CRYPTO_BUFFER_new(buffer.data(), buffer.size(), nullptr);

    if (!cb) {
        return 0;
    }

    *out = cb;
    return 1;
}
