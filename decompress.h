// ============================
// decompress.h
// ============================
#pragma once
#include "platform_win.h"
#include <string>


std::string decompress_gzip_deflate(const std::string& input);
std::string decompress_brotli(const std::string& input);