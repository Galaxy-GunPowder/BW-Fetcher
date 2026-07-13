#include "challenge_scripts.h"

#include "URL_to_DNS/URL_Parser.h"

#include <cctype>
#include <cstring>
#include <regex>
#include <unordered_set>
#include <vector>

namespace {

const std::regex SCRIPT_SRC_RE(R"(<script[^>]+src\s*=\s*["']([^"']+)["'])", std::regex::icase);

const std::regex LINK_MODULEPRELOAD_RE(
    R"(<link\b[^>]*\b(?:rel\s*=\s*["'][^"']*\bmodulepreload\b[^"']*["'][^>]*\bhref\s*=\s*["']([^"']+)["']|href\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["'][^"']*\bmodulepreload\b[^"']*["']))",
    std::regex::icase);

const std::regex LINK_PRELOAD_SCRIPT_RE(
    R"(<link\b[^>]*\b(?:rel\s*=\s*["'][^"']*\bpreload\b[^"']*["'][^>]*\bas\s*=\s*["']script["'][^>]*\bhref\s*=\s*["']([^"']+)["']|href\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["'][^"']*\bpreload\b[^"']*["'][^>]*\bas\s*=\s*["']script["']))",
    std::regex::icase);

const char* CHALLENGE_PATTERNS[] = {
    R"(/cdn-cgi/challenge-platform/)",
    R"(challenges\.cloudflare\.com)",
    R"(/akam/)",
    R"(bmak\.js)",
    R"(/datadome/)",
    R"(datadome\.co)",
    R"(px-cloud\.net)",
    R"(perimeterx\.net)",
    R"(/149e9513-)",
    R"(kasada\.io)",
    R"(/botjs/)",
    R"(/_Incapsula_Resource)",
    R"(recaptcha/api)",
    R"(hcaptcha\.com)",
    R"(challenges\.cloudflare\.com/turnstile)",
    R"(/js/[A-Za-z0-9_-]{8,}\.js)",
};

bool ci_starts_with(const std::string& s, const char* prefix) {
    const size_t n = std::strlen(prefix);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        char a = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
        char b = prefix[i];
        if (a != b) return false;
    }
    return true;
}

bool is_fetchable_subresource(const std::string& src) {
    if (src.empty()) return false;
    if (src[0] == '#') return false;
    if (ci_starts_with(src, "data:")) return false;
    if (ci_starts_with(src, "blob:")) return false;
    if (ci_starts_with(src, "javascript:")) return false;
    if (ci_starts_with(src, "vbscript:")) return false;
    if (ci_starts_with(src, "mailto:")) return false;
    if (ci_starts_with(src, "tel:")) return false;
    return true;
}

void append_link_hrefs(
    const std::regex& re,
    const std::string& html,
    const char* discovery_source,
    std::vector<std::pair<std::string, std::string>>& out) {
    for (std::sregex_iterator it(html.begin(), html.end(), re), end; it != end; ++it) {
        std::string href = (*it)[1].str();
        if (href.empty()) href = (*it)[2].str();
        if (!href.empty()) out.emplace_back(std::move(href), discovery_source);
    }
}

void collect_raw_candidates(
    const std::string& window,
    std::vector<std::pair<std::string, std::string>>& raw) {
    for (std::sregex_iterator it(window.begin(), window.end(), SCRIPT_SRC_RE), end; it != end; ++it) {
        raw.emplace_back((*it)[1].str(), "script");
    }
    append_link_hrefs(LINK_MODULEPRELOAD_RE, window, "link/modulepreload", raw);
    append_link_hrefs(LINK_PRELOAD_SCRIPT_RE, window, "link/preload", raw);
}

bool is_challenge_url(const std::string& url) {
    static const std::vector<std::regex> res = [] {
        std::vector<std::regex> v;
        for (const char* pat : CHALLENGE_PATTERNS) {
            v.emplace_back(pat, std::regex::icase);
        }
        return v;
    }();
    for (const auto& re : res) {
        if (std::regex_search(url, re)) return true;
    }
    return false;
}

std::string resolve_url(const std::string& src, const std::string& page_url) {
    try {
        ParsedURL base = parse_url(page_url);
        if (src.rfind("http://", 0) == 0 || src.rfind("https://", 0) == 0) return src;
        if (!src.empty() && src[0] == '/') {
            return "https://" + base.host + src;
        }
        if (src.rfind("//", 0) == 0) return "https:" + src;
        std::string path = base.path;
        size_t slash = path.rfind('/');
        if (slash != std::string::npos) path = path.substr(0, slash + 1);
        return "https://" + base.host + path + src;
    } catch (...) {
        return src;
    }
}

std::vector<DiscoveredSubresource> resolve_new_candidates(
    const std::vector<std::pair<std::string, std::string>>& raw,
    const std::string& page_url,
    std::unordered_set<std::string>& seen_abs,
    int max_count,
    int& found) {
    std::vector<DiscoveredSubresource> out;
    for (const auto& [src, source] : raw) {
        if (!is_fetchable_subresource(src)) continue;
        std::string abs = resolve_url(src, page_url);
        if (seen_abs.count(abs)) continue;
        seen_abs.insert(abs);
        out.push_back({abs, source});
        ++found;
        if (max_count > 0 && found >= max_count) break;
    }
    return out;
}

} // namespace

std::vector<std::string> extract_script_srcs(const std::string& html) {
    std::vector<std::string> out;
    for (std::sregex_iterator it(html.begin(), html.end(), SCRIPT_SRC_RE), end; it != end; ++it) {
        out.push_back((*it)[1].str());
    }
    return out;
}

std::vector<std::string> filter_challenge_script_urls(
    const std::vector<std::string>& srcs,
    const std::string& page_url) {
    std::unordered_set<std::string> seen;
    std::vector<std::string> out;
    for (const std::string& src : srcs) {
        std::string abs = resolve_url(src, page_url);
        if (seen.count(abs)) continue;
        if (is_challenge_url(abs) || is_challenge_url(src)) {
            seen.insert(abs);
            out.push_back(abs);
        }
    }
    return out;
}

std::vector<std::string> discover_challenge_scripts(
    const std::string& html,
    const std::string& page_url,
    int max_count) {
    auto srcs = extract_script_srcs(html);
    auto urls = filter_challenge_script_urls(srcs, page_url);
    if (max_count > 0 && static_cast<int>(urls.size()) > max_count) {
        urls.resize(static_cast<size_t>(max_count));
    }
    return urls;
}

std::vector<DiscoveredSubresource> discover_subresource_urls(
    const std::string& html,
    const std::string& page_url,
    int max_count) {
    std::vector<std::pair<std::string, std::string>> raw;
    collect_raw_candidates(html, raw);
    std::unordered_set<std::string> seen;
    int found = 0;
    return resolve_new_candidates(raw, page_url, seen, max_count, found);
}

IncrementalSubresourceScanner::IncrementalSubresourceScanner(std::string page_url, int max_count)
    : page_url_(std::move(page_url)), max_count_(max_count) {}

std::vector<DiscoveredSubresource> IncrementalSubresourceScanner::scan_window(size_t begin, size_t end) {
    if (begin >= end || end > buffer_.size()) return {};
    if (max_count_ > 0 && found_ >= max_count_) return {};
    std::vector<std::pair<std::string, std::string>> raw;
    collect_raw_candidates(buffer_.substr(begin, end - begin), raw);
    return resolve_new_candidates(raw, page_url_, seen_abs_, max_count_, found_);
}

std::vector<DiscoveredSubresource> IncrementalSubresourceScanner::feed(const char* data, size_t len) {
    if (!data || len == 0) return {};
    if (max_count_ > 0 && found_ >= max_count_) return {};
    buffer_.append(data, len);
    const size_t safe_end =
        buffer_.size() > kTailGuard ? buffer_.size() - kTailGuard : 0;
    if (safe_end <= scan_cursor_) return {};
    auto out = scan_window(scan_cursor_, safe_end);
    scan_cursor_ = safe_end;
    return out;
}

std::vector<DiscoveredSubresource> IncrementalSubresourceScanner::finalize() {
    if (scan_cursor_ >= buffer_.size()) return {};
    return scan_window(scan_cursor_, buffer_.size());
}
