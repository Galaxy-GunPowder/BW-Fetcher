#pragma once
#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

// Extract ``<script src="...">`` values from HTML (mirrors bw_fetcher_py).
std::vector<std::string> extract_script_srcs(const std::string& html);
std::vector<std::string> filter_challenge_script_urls(
    const std::vector<std::string>& srcs,
    const std::string& page_url);
std::vector<std::string> discover_challenge_scripts(
    const std::string& html,
    const std::string& page_url,
    int max_count);

// How the URL appeared in the HTML (before response Content-Type is known).
struct DiscoveredSubresource {
    std::string url;
    // ``script`` | ``link/preload`` | ``link/modulepreload``
    std::string discovery_source;
};

std::vector<DiscoveredSubresource> discover_subresource_urls(
    const std::string& html,
    const std::string& page_url,
    int max_count);

// Scan HTML incrementally as body DATA chunks arrive (browser preload-scanner style).
class IncrementalSubresourceScanner {
public:
    IncrementalSubresourceScanner(std::string page_url, int max_count);

    std::vector<DiscoveredSubresource> feed(const char* data, size_t len);
    std::vector<DiscoveredSubresource> finalize();

private:
    std::vector<DiscoveredSubresource> scan_window(size_t begin, size_t end);

    std::string page_url_;
    std::string buffer_;
    size_t scan_cursor_ = 0;
    std::unordered_set<std::string> seen_abs_;
    int max_count_;
    int found_ = 0;
    static constexpr size_t kTailGuard = 2048;
};
