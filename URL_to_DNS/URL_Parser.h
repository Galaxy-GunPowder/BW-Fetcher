// ============================
// URL_Parser.h
// ============================
#pragma once
#include <string>
#include <stdexcept>

struct ParsedURL {
    std::string scheme;

    std::string userinfo;   // optional
    std::string host;       // optional
    std::string port;       // optional

    std::string path;       // may be empty
    std::string query;      // optional
    std::string fragment;   // optional
};


// Parse URL string into scheme, host, port, path
ParsedURL parse_url(const std::string& url, const std::string& default_port = "443");
