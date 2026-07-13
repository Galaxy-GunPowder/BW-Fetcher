#include "html_catalog.h"

#include "URL_to_DNS/URL_Parser.h"

#include <cstring>
#include <regex>
#include <unordered_set>

namespace {

const std::regex INLINE_SCRIPT_RE(
    R"(<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)</script>)",
    std::regex::icase);

const std::regex FETCH_HINT_RE(
    R"((?:fetch\s*\(\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']|\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']))",
    std::regex::icase);

const std::regex A_HREF_RE(R"(<a\b[^>]+href\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex AREA_HREF_RE(R"(<area\b[^>]+href\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex IFRAME_SRC_RE(R"(<iframe\b[^>]+src\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex IMG_SRC_RE(R"(<img\b[^>]+src\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex FORM_ACTION_RE(R"(<form\b[^>]+action\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex EMBED_SRC_RE(R"(<embed\b[^>]+src\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex OBJECT_DATA_RE(R"(<object\b[^>]+data\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex MEDIA_SRC_RE(
    R"(<(?:video|audio|source)\b[^>]+src\s*=\s*["']([^"']+)["'])",
    std::regex::icase);
const std::regex BASE_HREF_RE(R"(<base\b[^>]+href\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex LINK_TAG_RE(R"(<link\b[^>]*>)", std::regex::icase);
const std::regex LINK_HREF_RE(R"(href\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex LINK_REL_RE(R"(rel\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex LINK_AS_RE(R"(as\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex LINK_TYPE_RE(R"(type\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex LINK_HREFLANG_RE(R"(hreflang\s*=\s*["']([^"']+)["'])", std::regex::icase);
const std::regex API_PATH_RE(R"(["'](/[^"'#\\s]{2,})["'])", std::regex::icase);
const std::regex SCRIPT_SRC_IN_HTML_RE(
    R"(<script\b[^>]+src\s*=\s*["']([^"']+)["'])",
    std::regex::icase);

bool ci_contains(const std::string& hay, const char* needle) {
    std::string h = hay;
    std::string n = needle;
    for (char& c : h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (char& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return h.find(n) != std::string::npos;
}

bool is_stylesheet_link(const std::string& tag) {
    if (ci_contains(tag, "stylesheet")) return true;
    std::smatch m;
    if (std::regex_search(tag, m, LINK_TYPE_RE)) {
        if (ci_contains(m[1].str(), "css")) return true;
    }
    return false;
}

bool is_fetched_link_tag(const std::string& tag) {
    if (is_stylesheet_link(tag)) return true;
    if (ci_contains(tag, "modulepreload")) return true;
    if (ci_contains(tag, "preload") && ci_contains(tag, "script")) return true;
    return false;
}

std::string resolve_abs(const std::string& src, const std::string& page_url) {
    try {
        ParsedURL base = parse_url(page_url);
        if (src.rfind("http://", 0) == 0 || src.rfind("https://", 0) == 0) return src;
        if (!src.empty() && src[0] == '/') return "https://" + base.host + src;
        if (src.rfind("//", 0) == 0) return "https:" + src;
        std::string path = base.path;
        size_t slash = path.rfind('/');
        if (slash != std::string::npos) path = path.substr(0, slash + 1);
        return "https://" + base.host + path + src;
    } catch (...) {
        return src;
    }
}

bool is_catalogable_url(const std::string& src) {
    if (src.empty() || src[0] == '#') return false;
    auto lower_start = [](const std::string& s, const char* p) {
        const size_t n = std::strlen(p);
        if (s.size() < n) return false;
        for (size_t i = 0; i < n; ++i) {
            if (std::tolower(static_cast<unsigned char>(s[i])) != p[i]) return false;
        }
        return true;
    };
    if (lower_start(src, "data:")) return false;
    if (lower_start(src, "blob:")) return false;
    if (lower_start(src, "javascript:")) return false;
    if (lower_start(src, "mailto:")) return false;
    if (lower_start(src, "tel:")) return false;
    return true;
}

struct SeenKey {
    std::string discovery_source;
    std::string url;
    bool operator==(const SeenKey& o) const {
        return discovery_source == o.discovery_source && url == o.url;
    }
};

struct SeenHash {
    size_t operator()(const SeenKey& k) const {
        return std::hash<std::string>{}(k.discovery_source + '\0' + k.url);
    }
};

void add_url_entry(
    std::vector<PresentCatalogEntry>& out,
    std::unordered_set<SeenKey, SeenHash>& seen,
    const std::string& src,
    const std::string& page_url,
    const std::unordered_set<std::string>& fetched_abs,
    const std::string& discovery_source,
    int& seq,
    const std::string& label = "") {
    if (!is_catalogable_url(src)) return;
    const std::string abs = resolve_abs(src, page_url);
    if (fetched_abs.count(abs)) return;
    SeenKey key{discovery_source, abs};
    if (seen.count(key)) return;
    seen.insert(key);
    out.push_back({abs, discovery_source, "url", "", label, seq++});
}

void scan_link_tags(
    const std::string& html,
    const std::string& page_url,
    const std::unordered_set<std::string>& fetched_abs,
    std::vector<PresentCatalogEntry>& out,
    std::unordered_set<SeenKey, SeenHash>& seen,
    int& seq) {
    for (std::sregex_iterator it(html.begin(), html.end(), LINK_TAG_RE), end; it != end; ++it) {
        const std::string tag = (*it)[0].str();
        if (is_fetched_link_tag(tag)) continue;
        std::smatch href_m;
        if (!std::regex_search(tag, href_m, LINK_HREF_RE)) continue;
        std::string label;
        std::smatch rel_m;
        if (std::regex_search(tag, rel_m, LINK_REL_RE)) label = rel_m[1].str();
        std::smatch hl_m;
        if (std::regex_search(tag, hl_m, LINK_HREFLANG_RE)) {
            if (!label.empty()) label += '-';
            label += hl_m[1].str();
        }
        add_url_entry(out, seen, href_m[1].str(), page_url, fetched_abs, "links/link", seq, label);
    }
}

void scan_api_paths(
    const std::string& text,
    const std::string& page_url,
    const std::unordered_set<std::string>& fetched_abs,
    std::vector<PresentCatalogEntry>& out,
    std::unordered_set<SeenKey, SeenHash>& seen,
    int& seq) {
    for (std::sregex_iterator it(text.begin(), text.end(), API_PATH_RE), end; it != end; ++it) {
        const std::string path = (*it)[1].str();
        if (path.size() < 3) continue;
        if (path.rfind("/sportsbook-static/", 0) == 0) continue;
        std::string label = path;
        if (label.size() > 48) label = label.substr(0, 48);
        add_url_entry(out, seen, path, page_url, fetched_abs, "api/path", seq, label);
    }
}

void scan_regex_urls(
    const std::regex& re,
    const std::string& html,
    const std::string& page_url,
    const std::unordered_set<std::string>& fetched_abs,
    const char* discovery_source,
    std::vector<PresentCatalogEntry>& out,
    std::unordered_set<SeenKey, SeenHash>& seen,
    int& seq) {
    for (std::sregex_iterator it(html.begin(), html.end(), re), end; it != end; ++it) {
        add_url_entry(out, seen, (*it)[1].str(), page_url, fetched_abs, discovery_source, seq);
    }
}

} // namespace

std::vector<PresentCatalogEntry> catalog_present_resources(
    const std::string& html,
    const std::string& page_url,
    const std::unordered_set<std::string>& fetched_abs,
    int start_seq) {
    std::vector<PresentCatalogEntry> out;
    std::unordered_set<SeenKey, SeenHash> seen;
    int seq = start_seq;

    scan_regex_urls(A_HREF_RE, html, page_url, fetched_abs, "links/a", out, seen, seq);
    scan_regex_urls(AREA_HREF_RE, html, page_url, fetched_abs, "links/area", out, seen, seq);
    scan_regex_urls(IFRAME_SRC_RE, html, page_url, fetched_abs, "links/iframe", out, seen, seq);
    scan_regex_urls(IMG_SRC_RE, html, page_url, fetched_abs, "links/img", out, seen, seq);
    scan_regex_urls(FORM_ACTION_RE, html, page_url, fetched_abs, "links/form", out, seen, seq);
    scan_regex_urls(EMBED_SRC_RE, html, page_url, fetched_abs, "links/embed", out, seen, seq);
    scan_regex_urls(OBJECT_DATA_RE, html, page_url, fetched_abs, "links/object", out, seen, seq);
    scan_regex_urls(MEDIA_SRC_RE, html, page_url, fetched_abs, "links/media", out, seen, seq);
    scan_regex_urls(BASE_HREF_RE, html, page_url, fetched_abs, "links/base", out, seen, seq);
    scan_link_tags(html, page_url, fetched_abs, out, seen, seq);

    // ``<script src>`` not fetched (cap / cross-origin pending) → present only.
    for (std::sregex_iterator it(html.begin(), html.end(), SCRIPT_SRC_IN_HTML_RE), end; it != end; ++it) {
        add_url_entry(out, seen, (*it)[1].str(), page_url, fetched_abs, "links/script", seq);
    }

    std::string inline_blob;
    int inline_idx = 0;
    for (std::sregex_iterator it(html.begin(), html.end(), INLINE_SCRIPT_RE), end; it != end; ++it) {
        std::string body = (*it)[1].str();
        if (body.find_first_not_of(" \t\r\n") == std::string::npos) continue;
        ++inline_idx;
        const std::string key = "inline:" + std::to_string(inline_idx);
        SeenKey sk{"inline_script", key};
        if (seen.count(sk)) continue;
        seen.insert(sk);
        out.push_back({"", "inline_script", "js", body, "inline-" + std::to_string(inline_idx), seq++});
        inline_blob += body;
        inline_blob += '\n';
    }

    for (std::sregex_iterator it(inline_blob.begin(), inline_blob.end(), FETCH_HINT_RE), end; it != end;
         ++it) {
        std::string hint = (*it)[1].str();
        if (hint.empty()) hint = (*it)[2].str();
        if (hint.empty()) hint = (*it)[3].str();
        add_url_entry(out, seen, hint, page_url, fetched_abs, "fetch/hint", seq);
    }

    scan_api_paths(inline_blob, page_url, fetched_abs, out, seen, seq);
    scan_api_paths(html, page_url, fetched_abs, out, seen, seq);

    return out;
}
