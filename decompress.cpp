// ============================
// decompress.cpp
// ============================
#include "platform_win.h"
#include "decompress.h"
#include <zlib.h>
#include <brotli/decode.h>
#include <iostream>
#include <vector>


std::string decompress_gzip_deflate(const std::string& input) {
    z_stream zs{};
    if (inflateInit2(&zs, 32 + MAX_WBITS) != Z_OK) { // 32 => auto-detect gzip OR zlib/deflate
        std::cerr << "zlib inflateInit2 failed\n";
        return {};
    }


    zs.next_in = (Bytef*)input.data();
    zs.avail_in = static_cast<uInt>(input.size());


    std::string out;
    char buffer[8192];


    int ret;
    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer);
        zs.avail_out = sizeof(buffer);
        ret = inflate(&zs, Z_NO_FLUSH);


        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            std::cerr << "zlib inflate failed\n";
            break;
        }
        out.append(buffer, sizeof(buffer) - zs.avail_out);

        // Z_BUF_ERROR here means no progress is possible — we always hand inflate
        // a fresh full output buffer, so this only happens when the input is
        // exhausted/truncated before Z_STREAM_END. Break instead of spinning
        // forever (a truncated or empty gzip body would otherwise hang).
        if (ret == Z_BUF_ERROR) break;
    } while (ret != Z_STREAM_END);


    inflateEnd(&zs);
    return out;
}


std::string decompress_brotli(const std::string& input) {
    // Streaming decode so there is no fixed output cap / silent truncation.
    BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!state) {
        std::cerr << "Brotli: failed to create decoder\n";
        return {};
    }

    size_t         avail_in = input.size();
    const uint8_t* next_in  = reinterpret_cast<const uint8_t*>(input.data());

    constexpr size_t CHUNK = 64 * 1024;
    std::vector<uint8_t> buffer(CHUNK);
    std::string out;

    BrotliDecoderResult res;
    do {
        size_t   avail_out = CHUNK;
        uint8_t* next_out  = buffer.data();
        res = BrotliDecoderDecompressStream(state, &avail_in, &next_in,
                                            &avail_out, &next_out, nullptr);
        out.append(reinterpret_cast<const char*>(buffer.data()), CHUNK - avail_out);
    } while (res == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

    BrotliDecoderDestroyInstance(state);

    if (res != BROTLI_DECODER_RESULT_SUCCESS) {
        std::cerr << "Brotli decompression failed\n";
        return {};
    }
    return out;
}