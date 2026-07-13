#pragma once
#include <string>
#include <unordered_set>
#include <vector>

// A URL or inline block found in HTML. ``disposition`` is always ``present`` here;
// fetched resources are written separately from FetchResult.
struct PresentCatalogEntry {
    std::string url;
    std::string discovery_source;  // links/a, links/img, inline_script, fetch/hint, api/path, ...
    std::string content_kind;      // url | js
    std::string body;              // non-empty for inline_script
    std::string label;             // optional viewer hint (hreflang, rel, path basename)
    int catalog_seq = 0;
};

// Catalog every non-CSS URL / inline script / JS URL hint in ``html`` that was not
// already fetched (``fetched_abs`` holds absolute URLs of primary + subresource GETs).
std::vector<PresentCatalogEntry> catalog_present_resources(
    const std::string& html,
    const std::string& page_url,
    const std::unordered_set<std::string>& fetched_abs,
    int start_seq = 1);
