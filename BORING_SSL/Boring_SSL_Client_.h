#pragma once
#include "../platform_win.h"
#include <openssl/ssl.h>
#include <string>
#include "Profile_Loader/tls_config.h"

class Boring_SSL_Client {
public:
    explicit Boring_SSL_Client(const TLS_Config& cfg);
    ~Boring_SSL_Client();
    std::pair<SSL*, std::string> SSL_Handshake(SOCKET sock, const std::string& host,const TLS_Config& cfg);


private:
    SSL_CTX* ctx;
};
