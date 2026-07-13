#include "platform_win.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

#include "fetcher.h"
#include "html_catalog.h"
#include "URL_to_DNS/URL_Parser.h"
#include "BORING_SSL/Profile_Loader/tls_profiles.h"
#include <chrono>
#include <ctime>

namespace {

void print_usage(const char* argv0) {
    std::cerr <<
        "BW-Fetcher - Chrome/Firefox TLS-fingerprinting HTTP/2 fetcher\n\n"
        "Usage:\n"
        "  " << argv0 << " [URL] [options]\n\n"
        "Options:\n"
        "  --url <url>           Target URL (or pass it positionally)\n"
        "  --also-fetch <url>    Additional GET after primary (repeatable;\n"
        "                        reuses HTTP/2 connection on same host)\n"
        "  --auto-challenge-scripts  After primary, discover + fetch challenge\n"
        "                        <script src> URLs from the HTML body\n"
        "  --max-challenge-scripts <n>  Cap for --auto-challenge-scripts (default: 5)\n"
        "  --fetch-subresources    While the HTML body streams in, scan for\n"
        "                        <script src> (+ preload hints) and GET each URL\n"
        "                        on the same HTTP/2 connection when same-host\n"
        "  --max-subresources <n>  Cap for --fetch-subresources (default: 32)\n"
        "  --out-dir <dir>         Store root (default: captures/ when using\n"
        "                        --fetch-subresources); each run creates\n"
        "                        <dir>/<timestamp>_<host>/requests/...\n"
        "  --run-name <label>    Optional folder label (default: target host)\n"
        "  --also-out-dir <dir>  Write also-fetch bodies as also_0.bin, ...\n"
        "  --profile <name>      Browser profile (default: Chrome143)\n"
        "  --out <file|->        Write primary body to file, or '-' for stdout\n"
        "                        (default: captured_page.html)\n"
        "  --proxy <host:port>   Route through a SOCKS5 proxy\n"
        "  --proxy-user <user>   SOCKS5 username (or env BW_FETCHER_PROXY_USER)\n"
        "  --proxy-pass <pass>   SOCKS5 password (or env BW_FETCHER_PROXY_PASS)\n"
        "  --max-redirects <n>   Redirect limit (default: 5)\n"
        "  --timeout <ms>        Per-request event-loop timeout (default: 30000)\n"
        "  --report <file|->     After the batch, write a consolidated run report\n"
        "                        ('-' = stderr). Verdict, signals, roll-up.\n"
        "  --list-profiles       Print available profiles and exit\n"
        "  -h, --help            Show this help\n"
        "\n"
        "Env:\n"
        "  BW_FETCHER_VERBOSE    Set to enable per-request diagnostics on stderr\n"
        "  BW_FETCHER_PROXY_USER/_PASS  SOCKS5 creds (keeps them off the argv)\n";
}

std::string json_escape(const std::string& s) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[(c >> 4) & 0xF];
                    out += hex[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

void write_headers_json(std::ostream& os, const std::map<std::string, std::string>& headers) {
    os << ",\"headers\":{";
    bool first = true;
    for (const auto& kv : headers) {
        if (!kv.first.empty() && kv.first[0] == ':') continue;
        if (!first) os << ",";
        first = false;
        os << "\"" << json_escape(kv.first) << "\":\""
           << json_escape(kv.second) << "\"";
    }
    os << "}";
}

int parse_int_arg(const std::string& v, const char* flag, int fallback, bool& ok) {
    int out = fallback;
    auto res = std::from_chars(v.data(), v.data() + v.size(), out);
    if (res.ec != std::errc() || res.ptr != v.data() + v.size()) {
        std::cerr << "[ERROR] " << flag << " expects an integer, got '" << v << "'\n";
        ok = false;
        return fallback;
    }
    return out;
}

std::string take_value(int argc, char** argv, int& i, bool& ok) {
    if (i + 1 >= argc) {
        std::cerr << "[ERROR] Missing value for " << argv[i] << "\n";
        ok = false;
        return "";
    }
    return argv[++i];
}

bool write_body_file(const std::string& path, const std::string& body) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    f.write(body.data(), static_cast<std::streamsize>(body.size()));
    return static_cast<bool>(f);
}

void emit_fetch_fields(
    std::ostream& os,
    const FetchResult& res,
    const std::string& profile,
    const std::string& out_path,
    bool include_out) {
    os << "\"status\":" << res.status
       << ",\"bytes\":" << res.body.size()
       << ",\"ttfb_ms\":" << res.ttfb_ms
       << ",\"profile\":\"" << json_escape(profile) << "\""
       << ",\"url\":\"" << json_escape(res.final_url) << "\""
       << ",\"ok\":" << (res.ok ? "true" : "false");
    if (res.request_seq >= 0) {
        os << ",\"request_seq\":" << res.request_seq;
    }
    if (!res.role.empty()) {
        os << ",\"role\":\"" << json_escape(res.role) << "\"";
    }
    if (res.h2_stream_id >= 0) {
        os << ",\"h2_stream_id\":" << res.h2_stream_id;
    }
    if (!res.discovery_source.empty()) {
        os << ",\"discovery_source\":\"" << json_escape(res.discovery_source) << "\"";
    }
    if (!res.content_kind.empty()) {
        os << ",\"content_kind\":\"" << json_escape(res.content_kind) << "\"";
    }
    if (!res.error.empty()) {
        os << ",\"error\":\"" << json_escape(res.error) << "\"";
    }
    if (include_out) {
        os << ",\"out\":\"" << json_escape(out_path) << "\"";
    }
    write_headers_json(os, res.headers);
}

std::string sanitize_path_label(std::string s) {
    for (char& c : s) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"'
            || c == '<' || c == '>' || c == '|' || c == '&' || c == '=') {
            c = '_';
        }
    }
    while (!s.empty() && (s.back() == '.' || s.back() == ' ' || s.back() == '_')) s.pop_back();
    if (s.empty()) s = "unknown";
    return s;
}

std::string url_path_slug(const std::string& url) {
    try {
        ParsedURL parsed = parse_url(url);
        std::string slug = parsed.path;
        const size_t slash = slug.rfind('/');
        if (slash != std::string::npos && slash + 1 < slug.size()) {
            slug = slug.substr(slash + 1);
        }
        if (slug.empty() || slug == "/") slug = parsed.host;
        slug = sanitize_path_label(slug);
        if (slug.size() > 56) slug = slug.substr(0, 56);
        return slug.empty() ? "resource" : slug;
    } catch (...) {
        return "resource";
    }
}

std::filesystem::path capture_category_dir(const FetchResult& res) {
    namespace fs = std::filesystem;
    const std::string kind = res.content_kind.empty() ? "binary" : res.content_kind;
    if (res.role == "primary" || res.discovery_source == "primary") {
        return fs::path("primary") / kind;
    }
    if (res.discovery_source == "script") {
        return fs::path("script") / kind;
    }
    if (res.discovery_source == "link/preload") {
        return fs::path("link") / "preload" / kind;
    }
    if (res.discovery_source == "link/modulepreload") {
        return fs::path("link") / "modulepreload" / kind;
    }
    if (res.discovery_source == "manual") {
        return fs::path("manual") / kind;
    }
    return fs::path("other") / kind;
}

std::string body_filename(const FetchResult& res) {
    const std::string& kind = res.content_kind.empty() ? "binary" : res.content_kind;
    if (kind == "html") return "body.html";
    if (kind == "js") return "body.js";
    if (kind == "json") return "body.json";
    if (kind == "css") return "body.css";
    if (kind == "wasm") return "body.wasm";
    if (kind == "text") return "body.txt";
    return "body.bin";
}

std::string request_folder_name(const FetchResult& res) {
    char seq_buf[8];
    std::snprintf(seq_buf, sizeof(seq_buf), "%03d", res.request_seq);
    std::string name = seq_buf;
    name += '-';
    if (res.role == "primary") {
        name += "primary";
    } else {
        name += url_path_slug(res.final_url);
    }
    return name;
}

std::string unique_request_dir(
    const std::filesystem::path& requests_root,
    const std::string& base_name) {
    namespace fs = std::filesystem;
    fs::path dir = requests_root / base_name;
    if (!fs::exists(dir)) return base_name;
    for (int n = 2; n < 1000; ++n) {
        std::string candidate = base_name + "_" + std::to_string(n);
        if (!fs::exists(requests_root / candidate)) return candidate;
    }
    return base_name + "_dup";
}

bool write_request_meta(const std::filesystem::path& meta_path, const FetchResult& res) {
    std::ofstream meta(meta_path);
    if (!meta.is_open()) return false;
    meta << "{\n"
         << "  \"disposition\": \"fetched\",\n"
         << "  \"request_seq\": " << res.request_seq << ",\n"
         << "  \"role\": \"" << json_escape(res.role) << "\",\n"
         << "  \"url\": \"" << json_escape(res.final_url) << "\",\n"
         << "  \"status\": " << res.status << ",\n"
         << "  \"bytes\": " << res.body.size() << ",\n"
         << "  \"ttfb_ms\": " << res.ttfb_ms;
    if (!res.discovery_source.empty()) {
        meta << ",\n  \"discovery_source\": \"" << json_escape(res.discovery_source) << "\"";
    }
    if (!res.content_kind.empty()) {
        meta << ",\n  \"content_kind\": \"" << json_escape(res.content_kind) << "\"";
    }
    if (res.h2_stream_id >= 0) {
        meta << ",\n  \"h2_stream_id\": " << res.h2_stream_id;
    }
    meta << "\n}\n";
    return static_cast<bool>(meta);
}

std::filesystem::path present_category_dir(const PresentCatalogEntry& entry) {
    namespace fs = std::filesystem;
    fs::path dir;
    std::string rest = entry.discovery_source;
    for (size_t pos = 0; pos <= rest.size();) {
        const size_t slash = rest.find('/', pos);
        const std::string part =
            (slash == std::string::npos) ? rest.substr(pos) : rest.substr(pos, slash - pos);
        if (!part.empty()) dir /= part;
        if (slash == std::string::npos) break;
        pos = slash + 1;
    }
    return dir;
}

std::string present_folder_name(const PresentCatalogEntry& entry) {
    char seq_buf[8];
    std::snprintf(seq_buf, sizeof(seq_buf), "%03d", entry.catalog_seq);
    std::string name = seq_buf;
    name += '-';
    if (entry.discovery_source == "inline_script") {
        name += entry.label.empty() ? "inline" : sanitize_path_label(entry.label);
    } else if (!entry.label.empty()) {
        name += sanitize_path_label(entry.label);
    } else {
        name += url_path_slug(entry.url);
    }
    return name;
}

bool write_present_meta(
    const std::filesystem::path& meta_path,
    const PresentCatalogEntry& entry) {
    std::ofstream meta(meta_path);
    if (!meta.is_open()) return false;
    meta << "{\n"
         << "  \"disposition\": \"present\",\n"
         << "  \"catalog_seq\": " << entry.catalog_seq << ",\n"
         << "  \"discovery_source\": \"" << json_escape(entry.discovery_source) << "\",\n"
         << "  \"content_kind\": \"" << json_escape(entry.content_kind) << "\"";
    if (!entry.url.empty()) {
        meta << ",\n  \"url\": \"" << json_escape(entry.url) << "\"";
    }
    if (!entry.label.empty()) {
        meta << ",\n  \"label\": \"" << json_escape(entry.label) << "\"";
    }
    if (!entry.body.empty()) {
        meta << ",\n  \"bytes\": " << entry.body.size();
    }
    meta << "\n}\n";
    return static_cast<bool>(meta);
}

std::string write_present_entry(
    const std::filesystem::path& present_root,
    const PresentCatalogEntry& entry) {
    namespace fs = std::filesystem;
    const fs::path type_root = present_root / present_category_dir(entry);
    fs::create_directories(type_root);
    const std::string folder = unique_request_dir(type_root, present_folder_name(entry));
    const fs::path dir = type_root / folder;
    fs::create_directories(dir);
    fs::path artifact_path;
    if (entry.content_kind == "js") {
        artifact_path = dir / "body.js";
        if (!write_body_file(artifact_path.string(), entry.body)) return "";
    } else {
        artifact_path = dir / "url.txt";
        if (!write_body_file(artifact_path.string(), entry.url)) return "";
    }
    write_present_meta(dir / "meta.json", entry);
    return artifact_path.string();
}

std::string write_capture_request(
    const std::filesystem::path& requests_root,
    const FetchResult& res) {
    namespace fs = std::filesystem;
    const fs::path fetched_root = requests_root / "fetched";
    const fs::path type_root = fetched_root / capture_category_dir(res);
    fs::create_directories(type_root);
    const std::string folder = unique_request_dir(type_root, request_folder_name(res));
    const fs::path dir = type_root / folder;
    fs::create_directories(dir);
    const fs::path body_path = dir / body_filename(res);
    if (!write_body_file(body_path.string(), res.body)) return "";
    write_request_meta(dir / "meta.json", res);
    return body_path.string();
}

std::string host_from_url(const std::string& url) {
    try {
        return parse_url(url).host;
    } catch (...) {
        return "unknown";
    }
}

std::string run_timestamp_local() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm);
    return buf;
}

std::filesystem::path allocate_run_dir(
    const std::filesystem::path& store_root,
    const std::string& url,
    const std::string& run_name) {
    namespace fs = std::filesystem;
    const std::string label =
        run_name.empty() ? sanitize_path_label(host_from_url(url)) : sanitize_path_label(run_name);
    const std::string stamp = run_timestamp_local();
    fs::path candidate = store_root / (stamp + "_" + label);
    for (int n = 2; fs::exists(candidate); ++n) {
        candidate = store_root / (stamp + "_" + label + "_" + std::to_string(n));
    }
    fs::create_directories(candidate);
    return candidate;
}

bool write_run_json(
    const std::filesystem::path& run_dir,
    const std::string& target_url,
    const FetchResult& primary,
    const std::string& profile,
    int fetched_count,
    int present_count) {
    std::ofstream f(run_dir / "run.json");
    if (!f.is_open()) return false;
    f << "{\n"
      << "  \"run_id\": \"" << json_escape(run_dir.filename().string()) << "\",\n"
      << "  \"target_url\": \"" << json_escape(target_url) << "\",\n"
      << "  \"final_url\": \"" << json_escape(primary.final_url) << "\",\n"
      << "  \"profile\": \"" << json_escape(profile) << "\",\n"
      << "  \"status\": " << primary.status << ",\n"
      << "  \"ok\": " << (primary.ok ? "true" : "false") << ",\n"
      << "  \"fetched_count\": " << fetched_count << ",\n"
      << "  \"present_count\": " << present_count << ",\n"
      << "  \"catalog\": \"catalog.json\"\n"
      << "}\n";
    return static_cast<bool>(f);
}

void write_catalog_json(const std::filesystem::path& run_dir) {
    namespace fs = std::filesystem;
    const fs::path requests = run_dir / "requests";
    if (!fs::is_directory(requests)) return;

    struct Row {
        int seq = 0;
        std::string disposition;
        std::string rel_path;
        std::string discovery_source;
        std::string content_kind;
        std::string url;
        int bytes = -1;
        std::string artifact;
    };
    std::vector<Row> rows;

    for (const auto& meta_path : fs::recursive_directory_iterator(requests)) {
        if (meta_path.path().filename() != "meta.json") continue;
        std::ifstream in(meta_path.path());
        if (!in.is_open()) continue;
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

        auto extract_string = [&](const char* key) -> std::string {
            const std::string needle = std::string("\"") + key + "\": \"";
            const size_t pos = content.find(needle);
            if (pos == std::string::npos) return "";
            const size_t start = pos + needle.size();
            const size_t end = content.find('"', start);
            if (end == std::string::npos) return "";
            return content.substr(start, end - start);
        };
        auto extract_int = [&](const char* key, int fallback) -> int {
            const std::string needle = std::string("\"") + key + "\": ";
            const size_t pos = content.find(needle);
            if (pos == std::string::npos) return fallback;
            const size_t start = pos + needle.size();
            return std::atoi(content.c_str() + start);
        };

        Row row;
        row.disposition = extract_string("disposition");
        if (row.disposition.empty()) continue;
        row.discovery_source = extract_string("discovery_source");
        row.content_kind = extract_string("content_kind");
        row.url = extract_string("url");
        row.bytes = extract_int("bytes", -1);
        row.seq = row.disposition == "fetched"
            ? extract_int("request_seq", 0)
            : extract_int("catalog_seq", 0);
        row.rel_path = fs::relative(meta_path.path().parent_path(), run_dir).string();
        for (const auto& name : {"body.html", "body.js", "body.json", "body.bin", "body.txt", "url.txt"}) {
            if (fs::exists(meta_path.path().parent_path() / name)) {
                row.artifact = name;
                break;
            }
        }
        rows.push_back(std::move(row));
    }

    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.disposition != b.disposition) return a.disposition < b.disposition;
        return a.seq < b.seq;
    });

    std::ofstream out(run_dir / "catalog.json");
    if (!out.is_open()) return;
    out << "{\n  \"entries\": [\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        const Row& r = rows[i];
        if (i) out << ",\n";
        out << "    {\n"
            << "      \"disposition\": \"" << json_escape(r.disposition) << "\",\n"
            << "      \"seq\": " << r.seq << ",\n"
            << "      \"path\": \"" << json_escape(r.rel_path) << "\",\n"
            << "      \"discovery_source\": \"" << json_escape(r.discovery_source) << "\",\n"
            << "      \"content_kind\": \"" << json_escape(r.content_kind) << "\"";
        if (!r.url.empty()) {
            out << ",\n      \"url\": \"" << json_escape(r.url) << "\"";
        }
        if (r.bytes >= 0) {
            out << ",\n      \"bytes\": " << r.bytes;
        }
        if (!r.artifact.empty()) {
            out << ",\n      \"artifact\": \"" << json_escape(r.artifact) << "\"";
        }
        out << "\n    }";
    }
    out << "\n  ]\n}\n";
}

// ---------------------------------------------------------------------------
// Finalized run report. Emitted once, after the whole batch (primary + every
// follow-through) has completed, so a single run answers "what happened and was
// I blocked?". Human-readable and allowed to be long. Written to stderr (or a
// file) so it never contaminates the machine-readable stdout payload.
// ---------------------------------------------------------------------------

std::string header_ci(const std::map<std::string, std::string>& h, const char* lower_key) {
    std::string key = lower_key;
    auto it = h.find(key);
    if (it != h.end()) return it->second;
    for (const auto& kv : h) {
        if (kv.first.size() != key.size()) continue;
        bool same = true;
        for (size_t i = 0; i < key.size(); ++i) {
            if (static_cast<char>(std::tolower(static_cast<unsigned char>(kv.first[i]))) != key[i]) {
                same = false;
                break;
            }
        }
        if (same) return kv.second;
    }
    return "";
}

std::string verdict_for(const FetchResult& r) {
    if (!r.ok)                            return "ERROR (no response)";
    if (r.status >= 200 && r.status < 300) return "PASSED";
    if (r.status == 401 || r.status == 403) return "BLOCKED";
    if (r.status == 429)                  return "RATE-LIMITED";
    if (r.status == 503)                  return "CHALLENGED";
    if (r.status >= 400)                  return "FAILED";
    return "HTTP " + std::to_string(r.status);
}

// Interesting anti-bot / CDN signal headers, in display order.
std::vector<std::string> bot_signals(const FetchResult& r) {
    static const char* keys[] = {
        "cf-ray", "cf-mitigated", "x-bot-score", "x-bot-verified-bot",
        "is-akamai-cdn", "x-datadome", "x-px", "x-px-block", "x-akamai-bmp",
        "retry-after", "x-amz-cf-id",
    };
    std::vector<std::string> found;
    for (const char* k : keys) {
        std::string v = header_ci(r.headers, k);
        if (!v.empty()) found.push_back(std::string(k) + "=" + v);
    }
    return found;
}

std::string pad(std::string s, size_t w) {
    if (s.size() < w) s.append(w - s.size(), ' ');
    return s;
}

// Content bucket for the report: prefer the fetcher's own classification, else
// derive it from the Content-Type header so plain fetches still get a kind.
std::string kind_of(const FetchResult& r) {
    if (!r.content_kind.empty()) return r.content_kind;
    std::string ct = header_ci(r.headers, "content-type");
    std::transform(ct.begin(), ct.end(), ct.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (ct.find("html") != std::string::npos)       return "html";
    if (ct.find("javascript") != std::string::npos) return "js";
    if (ct.find("json") != std::string::npos)        return "json";
    if (ct.find("css") != std::string::npos)         return "css";
    if (ct.find("wasm") != std::string::npos)        return "wasm";
    if (ct.rfind("text/", 0) == 0)                   return "text";
    if (ct.empty())                                  return "?";
    return "binary";
}

void write_run_report(
    std::ostream& os,
    const FetchOptions& opt,
    const MultiFetchResult& batch,
    const std::string& run_dir_str,
    int present_count) {

    const FetchResult& p = batch.primary;

    // Timestamp
    std::time_t now = std::time(nullptr);
    char ts[32] = {0};
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    const size_t follow = batch.also.size();

    os << "================ BW-Fetcher run report ================\n";
    os << "Target      : " << opt.url << "\n";
    os << "Profile     : " << opt.profile << "\n";
    os << "When        : " << ts << "\n";
    os << "Requests    : 1 primary + " << follow << " follow-through(s)\n\n";

    os << "--- Verdict ---\n";
    os << verdict_for(p);
    if (p.ok) os << "  (HTTP " << p.status << ")";
    if (!p.error.empty()) os << "  " << p.error;
    os << "\n\n";

    os << "--- Primary ---\n";
    os << "Final URL   : " << (p.final_url.empty() ? opt.url : p.final_url) << "\n";
    os << "Status      : " << p.status << "\n";
    os << "TTFB        : " << p.ttfb_ms << " ms\n";
    os << "Body        : " << p.body.size() << " bytes (" << kind_of(p) << ")\n";
    std::string server = header_ci(p.headers, "server");
    if (!server.empty())   os << "Server      : " << server << "\n";
    std::string ctype = header_ci(p.headers, "content-type");
    if (!ctype.empty())    os << "Content-Type: " << ctype << "\n";
    std::string setck = header_ci(p.headers, "set-cookie");
    os << "Cookies set : " << (setck.empty() ? "no" : "yes") << "\n";
    std::vector<std::string> sig = bot_signals(p);
    if (!sig.empty()) {
        os << "Bot signals : ";
        for (size_t i = 0; i < sig.size(); ++i) os << (i ? "; " : "") << sig[i];
        os << "\n";
    }
    os << "\n";

    if (follow > 0) {
        os << "--- Follow-throughs (" << follow << ") ---\n";
        os << "  " << pad("seq", 4) << pad("role", 12) << pad("source", 16)
           << pad("status", 8) << pad("kind", 8) << pad("bytes", 9) << "url\n";
        for (const FetchResult& s : batch.also) {
            os << "  " << pad(std::to_string(s.request_seq), 4)
               << pad(s.role.empty() ? "-" : s.role, 12)
               << pad(s.discovery_source.empty() ? "-" : s.discovery_source, 16)
               << pad(std::to_string(s.status), 8)
               << pad(kind_of(s), 8)
               << pad(std::to_string(s.body.size()), 9)
               << (s.final_url.empty() ? "-" : s.final_url) << "\n";
        }
        os << "\n";
    }

    // Roll-up
    int total = 1 + static_cast<int>(follow);
    int ok_count = (p.ok && p.status < 400) ? 1 : 0;
    int blocked = (p.status >= 400) ? 1 : 0;
    std::map<std::string, int> by_kind;
    by_kind[kind_of(p)]++;
    for (const FetchResult& s : batch.also) {
        if (s.ok && s.status < 400) ok_count++;
        if (s.status >= 400) blocked++;
        by_kind[kind_of(s)]++;
    }

    os << "--- Roll-up ---\n";
    os << "Total requests : " << total << "\n";
    os << "Succeeded      : " << ok_count << "\n";
    os << "Failed/blocked : " << (total - ok_count) << "\n";
    if (blocked > 0) os << "HTTP >= 400    : " << blocked << "\n";
    os << "By content kind: ";
    bool first = true;
    for (const auto& kv : by_kind) {
        os << (first ? "" : ", ") << kv.first << "=" << kv.second;
        first = false;
    }
    os << "\n";
    if (!run_dir_str.empty()) {
        os << "Run dir        : " << run_dir_str << "\n";
        os << "Present in HTML: " << present_count << " resource(s) not fetched\n";
    }
    os << "=======================================================\n";
}

} // namespace

int main(int argc, char** argv) {
    FetchOptions opt;
    opt.url = "https://www.waze.com/live-map";
    std::string out_path = "captured_page.html";
    std::string out_dir;
    std::string run_name;
    std::string also_out_dir;
    std::string report_path;   // --report target: "" = off, "-" = stderr, else file
    bool args_ok = true;

    for (int i = 1; i < argc && args_ok; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (a == "--list-profiles") {
            for (const auto& name : list_profiles()) std::cout << name << "\n";
            return 0;
        } else if (a == "--url") {
            opt.url = take_value(argc, argv, i, args_ok);
        } else if (a == "--also-fetch") {
            opt.also_fetch.push_back(take_value(argc, argv, i, args_ok));
        } else if (a == "--report") {
            report_path = take_value(argc, argv, i, args_ok);
        } else if (a == "--auto-challenge-scripts") {
            opt.auto_challenge_scripts = true;
        } else if (a == "--fetch-subresources") {
            opt.fetch_subresources = true;
        } else if (a == "--max-subresources") {
            std::string v = take_value(argc, argv, i, args_ok);
            if (args_ok) {
                int n = parse_int_arg(v, "--max-subresources", opt.max_subresources, args_ok);
                if (args_ok && n < 1) {
                    std::cerr << "[ERROR] --max-subresources must be >= 1\n";
                    args_ok = false;
                } else if (args_ok) {
                    opt.max_subresources = n;
                }
            }
        } else if (a == "--out-dir") {
            out_dir = take_value(argc, argv, i, args_ok);
        } else if (a == "--run-name") {
            run_name = take_value(argc, argv, i, args_ok);
        } else if (a == "--max-challenge-scripts") {
            std::string v = take_value(argc, argv, i, args_ok);
            if (args_ok) {
                int n = parse_int_arg(v, "--max-challenge-scripts", opt.max_challenge_scripts, args_ok);
                if (args_ok && n < 1) {
                    std::cerr << "[ERROR] --max-challenge-scripts must be >= 1\n";
                    args_ok = false;
                } else if (args_ok) {
                    opt.max_challenge_scripts = n;
                }
            }
        } else if (a == "--also-out-dir") {
            also_out_dir = take_value(argc, argv, i, args_ok);
        } else if (a == "--profile") {
            opt.profile = take_value(argc, argv, i, args_ok);
        } else if (a == "--out") {
            out_path = take_value(argc, argv, i, args_ok);
        } else if (a == "--max-redirects") {
            std::string v = take_value(argc, argv, i, args_ok);
            if (args_ok) {
                int n = parse_int_arg(v, "--max-redirects", opt.max_redirects, args_ok);
                if (args_ok && n < 1) {
                    std::cerr << "[ERROR] --max-redirects must be >= 1\n";
                    args_ok = false;
                } else if (args_ok) {
                    opt.max_redirects = n;
                }
            }
        } else if (a == "--timeout") {
            std::string v = take_value(argc, argv, i, args_ok);
            if (args_ok) {
                int n = parse_int_arg(v, "--timeout", opt.timeout_ms, args_ok);
                if (args_ok && n < 0) {
                    std::cerr << "[ERROR] --timeout must be >= 0 (0 disables)\n";
                    args_ok = false;
                } else if (args_ok) {
                    opt.timeout_ms = n;
                }
            }
        } else if (a == "--proxy") {
            std::string hp = take_value(argc, argv, i, args_ok);
            if (args_ok) {
                size_t colon = hp.rfind(':');
                if (colon == std::string::npos) {
                    std::cerr << "[ERROR] --proxy expects host:port\n";
                    args_ok = false;
                } else {
                    int port = parse_int_arg(hp.substr(colon + 1), "--proxy port", 0, args_ok);
                    if (args_ok && (port < 1 || port > 65535)) {
                        std::cerr << "[ERROR] --proxy port out of range: " << port << "\n";
                        args_ok = false;
                    } else if (args_ok) {
                        opt.proxy.enabled = true;
                        opt.proxy.host = hp.substr(0, colon);
                        opt.proxy.port = static_cast<uint16_t>(port);
                    }
                }
            }
        } else if (a == "--proxy-user") {
            opt.proxy.user = take_value(argc, argv, i, args_ok);
        } else if (a == "--proxy-pass") {
            opt.proxy.pass = take_value(argc, argv, i, args_ok);
        } else if (!a.empty() && a[0] == '-') {
            std::cerr << "[ERROR] Unknown option: " << a << "\n";
            args_ok = false;
        } else {
            opt.url = a;
        }
    }

    if (!args_ok) {
        print_usage(argv[0]);
        return 2;
    }

    if (opt.fetch_subresources && out_dir.empty()) {
        out_dir = "captures";
    }
    if (opt.fetch_subresources && out_path == "-") {
        std::cerr << "[ERROR] --fetch-subresources cannot use --out - (use --out-dir)\n";
        return 2;
    }
    if ((!opt.also_fetch.empty() || opt.auto_challenge_scripts) && also_out_dir.empty()) {
        std::cerr << "[ERROR] --also-fetch / --auto-challenge-scripts requires --also-out-dir\n";
        return 2;
    }

    if (opt.proxy.user.empty()) {
        if (const char* u = std::getenv("BW_FETCHER_PROXY_USER")) opt.proxy.user = u;
    }
    if (opt.proxy.pass.empty()) {
        if (const char* p = std::getenv("BW_FETCHER_PROXY_PASS")) opt.proxy.pass = p;
    }

    namespace fs = std::filesystem;
    fs::path store_root;
    fs::path run_dir;
    if (opt.fetch_subresources) {
        store_root = fs::path(out_dir);
        fs::create_directories(store_root);
        run_dir = allocate_run_dir(store_root, opt.url, run_name);
    }

    MultiFetchResult batch = fetch_multi(opt);
    FetchResult& res = batch.primary;

    int present_count = 0;
    auto emit_report = [&](const std::string& run_dir_str) {
        if (report_path.empty()) return;
        if (report_path == "-") {
            write_run_report(std::cerr, opt, batch, run_dir_str, present_count);
        } else {
            std::ofstream rf(report_path, std::ios::binary);
            if (rf) {
                write_run_report(rf, opt, batch, run_dir_str, present_count);
            } else {
                std::cerr << "[WARN] Could not open report file: " << report_path << "\n";
            }
        }
    };

    if (!res.ok) {
        std::cerr << "[ERROR] Fetch failed: " << res.error << "\n";
        emit_report("");
        return 1;
    }

    if (out_path == "-" && !opt.fetch_subresources) {
        std::cout.flush();
#ifdef _WIN32
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        std::cout.write(res.body.data(), static_cast<std::streamsize>(res.body.size()));
        std::cout.flush();
    } else {
        std::string primary_path = out_path;
        fs::path requests_root;

        if (opt.fetch_subresources) {
            requests_root = run_dir / "requests";
            fs::create_directories(requests_root);
            if (res.role.empty()) res.role = "primary";
            if (res.discovery_source.empty()) res.discovery_source = "primary";
            if (res.content_kind.empty()) res.content_kind = "html";
            primary_path = write_capture_request(requests_root, res);
            if (primary_path.empty()) {
                std::cerr << "[ERROR] Could not write primary capture under '" << run_dir.string()
                          << "'\n";
                return 1;
            }
        } else if (!write_body_file(primary_path, res.body)) {
            std::cerr << "[ERROR] Could not open '" << primary_path << "' for writing\n";
            return 1;
        }

        std::vector<std::string> also_out_paths;
        for (size_t i = 0; i < batch.also.size(); ++i) {
            std::string path;
            if (opt.fetch_subresources) {
                FetchResult& sub = batch.also[i];
                if (sub.role.empty()) sub.role = "subresource";
                path = write_capture_request(requests_root, sub);
            } else {
                path = also_out_dir;
                if (!path.empty() && path.back() != '/' && path.back() != '\\') path += "/";
                path += "also_" + std::to_string(i) + ".bin";
                if (batch.also[i].ok && !batch.also[i].body.empty()) {
                    if (!write_body_file(path, batch.also[i].body)) {
                        std::cerr << "[WARN] Could not write subresource body to " << path << "\n";
                    }
                }
            }
            also_out_paths.push_back(path);
        }

        if (opt.fetch_subresources) {
            std::unordered_set<std::string> fetched_abs;
            fetched_abs.insert(res.final_url);
            for (const FetchResult& sub : batch.also) {
                if (sub.ok && !sub.final_url.empty()) fetched_abs.insert(sub.final_url);
            }
            int max_seq = res.request_seq >= 0 ? res.request_seq : 0;
            for (const FetchResult& sub : batch.also) {
                if (sub.request_seq > max_seq) max_seq = sub.request_seq;
            }
            const int catalog_start = max_seq + 1;
            const std::vector<PresentCatalogEntry> present =
                catalog_present_resources(res.body, res.final_url, fetched_abs, catalog_start);
            const fs::path present_root = requests_root / "present";
            for (const PresentCatalogEntry& entry : present) {
                if (!write_present_entry(present_root, entry).empty()) ++present_count;
            }
            const int fetched_count = 1 + static_cast<int>(batch.also.size());
            write_run_json(run_dir, opt.url, res, opt.profile, fetched_count, present_count);
            write_catalog_json(run_dir);
        }

        std::cout << "{";
        emit_fetch_fields(std::cout, res, opt.profile, primary_path, true);
        if (opt.fetch_subresources) {
            std::cout << ",\"disposition\":\"fetched\""
                      << ",\"store_root\":\"" << json_escape(store_root.string()) << "\""
                      << ",\"run_dir\":\"" << json_escape(run_dir.string()) << "\""
                      << ",\"present_count\":" << present_count;
        }
        if (!batch.also.empty()) {
            std::cout << ",\"subresources\":[";
            for (size_t i = 0; i < batch.also.size(); ++i) {
                if (i) std::cout << ",";
                std::cout << "{";
                emit_fetch_fields(std::cout, batch.also[i], opt.profile, also_out_paths[i], true);
                if (opt.fetch_subresources) std::cout << ",\"disposition\":\"fetched\"";
                std::cout << "}";
            }
            std::cout << "]";
        }
        std::cout << "}\n";
    }

    emit_report(opt.fetch_subresources ? run_dir.string() : std::string());

    return 0;
}
