//
//  ZombieAPI.cpp
//
//  Created by Edward Amoruso on 2/18/26
//
//

#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <queue>
#include <random>
#include <curl/curl.h>

#define APP_VERSION 13.0708
#define RANDOM_FUZZ_LIMIT 7013

using namespace std;

// --- Configuration & Constants ---
const long DEFAULT_TIMEOUT = 15;
const size_t MAX_BODY_SIZE = 5 * 1024 * 1024;
constexpr int DEFAULT_CRAWL_DEPTH = 1;
constexpr int DEFAULT_THREADS = 10;
constexpr int DEFAULT_DELAY_MS = 0;

// Zombie scoring weights (Table V in methodology):
// Z(e) = w1*se + w2*me + w3*ve + w4*fe + w5*re
constexpr double W_SE = 0.16;  // reachability
constexpr double W_ME = 0.27;  // method divergence
constexpr double W_VE = 0.13;  // version inconsistency
constexpr double W_FE = 0.29;  // fuzz-induced deviation
constexpr double W_RE = 0.15;  // response anomalies vs baseline
// Threshold θ for classifying an endpoint as zombie (paper Eq. 2)
constexpr double THETA_ZOMBIE = 40.3;
// Lower reporting threshold to show near-zombie endpoints
constexpr double THETA_REPORTING = 25.0;

struct ZombieSignal {
    bool se = false;   // Reachability: endpoint responds with non-404 status (w1)
    bool me = false;   // Method divergence: responds to HTTP methods other than GET (w2)
    bool ve = false;   // Version inconsistency: persisted across deprecated versions (w3)
    bool fe = false;   // Fuzz deviation: fingerprint deviates from baseline 404 (w4)
    bool re = false;   // Response anomaly: anomalous vs declared behavior / body fingerprint mismatch (w5)
};

struct ZombieEvidence {
    string url;
    ZombieSignal signals;
    double z_score = 0.0;          // final Z(e) value
    void computeScore() {
        z_score = W_SE * signals.se  + W_ME * signals.me  + W_VE * signals.ve  + W_FE * signals.fe  + W_RE * signals.re;
    }
    bool is_zombie() const { return z_score >= THETA_ZOMBIE; }
    bool should_report() const    { return z_score >= THETA_REPORTING; }

    // --- Gap 4: deprecation-lifecycle evidence ---
    vector<string> lifecycle_violations;   // reasons this endpoint likely "should have been deprecated"
    double lifetime_penalty = 0.0;         // additional score boost for lifecycle violations (w6)

    static constexpr double LIFETIME_VIOLATION_WEIGHT = 0.10;   // w6: each lifecycle violation boosts zombie score
};

// --- Data Structures (moved up for forward declarations) ---
struct HttpResult {
    long status = 0;
    size_t size = 0;
    double timeSec = 0.0;
    string body;
    string headers;
    string effectiveUrl;
    bool success = false;
};

struct CLIOptions {
    string url;
    bool noVerifySsl = false;
    bool passiveRecon = false;
    bool headerProbe = false;
    bool changelogHunt = false;
    string outfile = "";
    bool diffFuzz = false;
    bool randomFuzz = false;
    bool apiOnly = false;
    string fuzzDict = "";
    int crawlDepth = DEFAULT_CRAWL_DEPTH;
    int threads = DEFAULT_THREADS;
    int delayMs = DEFAULT_DELAY_MS;
};

struct EndpointEvidence {
    string url;
    int score = 0;
    vector<string> signals;
};

// --- Learning Storage ---
unordered_set<string> g_learned_prefixes;
unordered_set<string> g_learned_tokens;
mutex g_learningMutex;

// ============================================================
// GLOBAL FUZZING WORDLISTS
// ============================================================

const vector<string> COMMON_API_PATHS = {
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
    "/data", "/data/v1","/data/v2","/data/v3","/data/v4",
    "/value", "/value/v1", "/value/v2", "/val", "/val/1",
    "/api/v1/users", "/api/v1/profiles", "/api/v1/products", "/api/v1/orders",
    "/api/v1/auth", "/api/v1/system", "/api/v1/movies", "/api/v1/books",
    "/api/v1/weather", "/api/v1/countries", "/api/v1/recipes", "/api/v1/cars",
    "/api/v1/search", "/api/v1/health", "/api/v1/status", "/api/v1/info",
    "/api/v1/docs", "/api/v1/api", "/api-docs",
    "/redoc", "/docs", "/swagger", "/swagger-ui", "/rapidoc"
};
const vector<string> prefixes = {
    "/api", "/v1", "/v2", "/v3", "v4", "/admin", "/internal",
    "/private", "/debug", "/beta", "/ghost", "/shadow",
    "/hidden", "/staging", "/man", "/tmp", "/dev", "/test"
};
const vector<string> words = {
    "endpoint", "api", "data", "dump", "users", "orders",
    "metrics", "keys", "auth", "config", "status", "version",
    "card", "cc", "inventory", "entry", "range", "credit"
};

// Forward declarations
bool IsApiResponse(const HttpResult& result);
vector<string> ExtractEndpoints(const string& content, const string& baseUrl);
vector<string> ExtractLinks(const string& html, const string& baseHost);
vector<HttpResult> CrawlConcurrent(const string& startUrl,
                                        int maxDepth,
                                        int threads,
                                        int delayMs);
void FuzzCommonEndpoints(const string& baseUrl, int threads, int delayMs);

// Forward declarations for hidden/zombie API discovery
void PassiveRecon(const string& baseUrl, int threads, int delayMs, bool noVerifySsl);
void HeaderProbe(const vector<string>& endpoints, int threads, int delayMs, bool noVerifySsl);
void ChangelogHunt(const string& baseUrl, int threads, int delayMs, bool noVerifySsl);
void DiffFuzz(const string& baseUrl, const vector<string>& paths,
              int threads, int delayMs, bool noVerifySsl);
vector<string> ExtractFromSourceMap(const string& mapJson);
vector<string> ExtractFromOpenApiSpec(const string& specBody, const string& baseUrl);
vector<string> ExpandAndProbeTemplatePaths(const string& specBody, const string& baseUrl,
                                            int delayMs, bool noVerifySsl);
string BodyFingerprint(const string& body);
void ProbeSubPaths(const string& baseUrl, const vector<string>& endpoints,
                   int threads, int delayMs, bool noVerifySsl);

// --- Thread Safe Logging ---
mutex g_print_mutex;
void SafePrint(const string& msg) {
    lock_guard<mutex> lock(g_print_mutex);
    cout << msg << endl;
    cout.flush();
}

// --- Thread Pool Implementation ---
class ThreadPool {
public:
    // Use plain int for activeTasks, guarded entirely by queue_mutex
    ThreadPool(size_t threads) : activeTasks(0), stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                for (;;) {
                    function<void()> task;
                    {
                        unique_lock<mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });
                        if (this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                        this->activeTasks++;
                    }
                    task();
                    {
                        unique_lock<mutex> lock(this->queue_mutex);
                        this->activeTasks--;
                        this->done_condition.notify_all();
                    }
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& f) {
        {
            unique_lock<mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    void waitAll() {
        unique_lock<mutex> lock(queue_mutex);
        done_condition.wait(lock, [this] {
            return tasks.empty() && activeTasks == 0;
        });
    }

    ~ThreadPool() {
        {
            unique_lock<mutex> lock(queue_mutex);
            stop = true;
            while (!tasks.empty()) tasks.pop();
        }
        condition.notify_all();
        done_condition.notify_all();
        for (thread& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    vector<thread> workers;
    queue<function<void()>> tasks;
    mutex queue_mutex;
    condition_variable condition;
    condition_variable done_condition;
    int activeTasks;  // FIX #3: plain int, always guarded by queue_mutex
    bool stop;
};

void PrintHelp() {
    cout << R"(
    ZombieAPI Usage:
      ZombieAPI <url> [options]

    Options:
    
        --help                Show this help message
        --no-verify-ssl       Disable SSL certificate verification
        --depth <n>           Crawl depth (default 1)
        --threads <n>         Number of concurrent threads (default 10)
        --delay <ms>          Delay between requests in ms (rate limiting)
        --outfile <file>      Save results to CSV file
        --fuzz-dict <file>    Dictionary file for --random-fuzz (one word per line)
        --api-only            Show only API endpoints in final report

    
    Zombie/Hidden API Discovery:
    
      --passive-recon       Mine JS bundles, source maps (.map), OpenAPI/Swagger,
                            specs, robots.txt, and sitemap.xml for undocumented or 
                            retired routes.
      --header-probe        Re-request discovered endpoints with manipulated Host,
                            X-Forwarded-For, X-Original-URL, and X-Rewrite-URL headers
                            to surface shadow routes bypassed by the API gateway.
      --changelog-hunt      Probe debug, actuator, and well-known paths
                            (e.g. /actuator/**, /_debug, /changelog, /.well-known/**)
                            that commonly expose internal or end-of-life endpoints.
      --diff-fuzz           Baseline-diff responses against a known-404 fingerprint;
                            routes with diverging body sizes or content are flagged
                            as potential hidden endpoints.
      --random-fuzz         Hybird Random plus Dictionary Fuzzing for endpoint 
                            discovery. (experimental)
    )" << endl;
}

// -----------------------------------------------------------
// Global containers for discovered API endpoints
// -----------------------------------------------------------

unordered_set<string> g_endpoints;
mutex g_endpointsMutex;

// --- RAII Wrapper for CURL ---
class CurlHandle {
    CURL* handle;
public:
    CurlHandle() : handle(curl_easy_init()) {}
    ~CurlHandle() {
        if (handle) curl_easy_cleanup(handle);
    }
    CURL* get() { return handle; }
    bool isValid() const { return handle != nullptr; }
};

// --- RAII Wrapper for curl_slist ---
struct CurlSlistFree {
    void operator()(curl_slist* p) const { if (p) curl_slist_free_all(p); }
};
using CurlSlistPtr = unique_ptr<curl_slist, CurlSlistFree>;

void LearnFromEndpoint(const string& url) {
    // Remove protocol + host
    size_t pos = url.find("://");
    string path;
    if (pos != string::npos) {
        size_t pathStart = url.find("/", pos + 3);
        if (pathStart != string::npos) {
            path = url.substr(pathStart);
        } else {
            path = "/";
        }
    } else {
        path = url;
    }

    vector<string> parts;
    stringstream ss(path);
    string item;

    while (getline(ss, item, '/')) {
        if (!item.empty()) parts.push_back(item);
    }

    lock_guard<mutex> lock(g_learningMutex);

    if (!parts.empty()) {
        g_learned_prefixes.insert("/" + parts[0]);
    }

    for (const auto& p : parts) {
        if (p.length() > 2 && p.length() < 30) {
            g_learned_tokens.insert(p);
        }
    }
}

void AddEndpoint(const string& ep) {
        lock_guard<mutex> lk(g_endpointsMutex);
        g_endpoints.insert(ep);

    // NEW: learn from it
    LearnFromEndpoint(ep);
}

// Safe integer parsing helper
int SafeParseInt(const char* str, const string& flagName) {
    try {
        return stoi(str);
    } catch (const invalid_argument&) {
        cerr << "❌ Invalid integer value for " << flagName << ": " << str << "\n";
        exit(1);
    } catch (const out_of_range&) {
        cerr << "❌ Value out of range for " << flagName << ": " << str << "\n";
        exit(1);
    }
}

CLIOptions ParseArgs(int argc, const char* argv[]) {
    CLIOptions opts;
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--help") {
            PrintHelp();
            exit(0);
        }
        else if (arg == "--no-verify-ssl")  opts.noVerifySsl = true;
        else if (arg == "--passive-recon")  opts.passiveRecon = true;
        else if (arg == "--header-probe")   opts.headerProbe = true;
        else if (arg == "--changelog-hunt") opts.changelogHunt = true;
        else if (arg == "--diff-fuzz")      opts.diffFuzz = true;
        else if (arg == "--random-fuzz") opts.randomFuzz = true;
        else if (arg == "--depth"   && i + 1 < argc) opts.crawlDepth = SafeParseInt(argv[++i], "--depth");
        else if (arg == "--threads" && i + 1 < argc) opts.threads    = SafeParseInt(argv[++i], "--threads");
        else if (arg == "--delay"   && i + 1 < argc) opts.delayMs    = SafeParseInt(argv[++i], "--delay");
        else if (arg == "--outfile" && i + 1 < argc) opts.outfile = argv[++i];
        else if (arg == "--fuzz-dict" && i + 1 < argc) opts.fuzzDict = argv[++i];
        else if (arg == "--api-only") opts.apiOnly = true;
        else if (arg[0] != '-') opts.url = arg;
        else {
            cerr << "❌ Unknown flag: " << arg << "\n";
            exit(1);
        }
    }
    return opts;
}

// --- CURL Callbacks ---
size_t WriteBodyCallback(void* contents, size_t size, size_t nmemb, string* s) {
    size_t totalSize = size * nmemb;
    // FIX #5: Silently discard overflow instead of aborting the transfer
    if (s->size() >= MAX_BODY_SIZE) return totalSize;
    size_t canWrite = min(totalSize, MAX_BODY_SIZE - s->size());
    s->append(static_cast<const char*>(contents), canWrite);
    return totalSize;
}

size_t WriteHeaderCallback(void* contents, size_t size, size_t nmemb, string* s) {
    size_t totalSize = size * nmemb;
    s->append(static_cast<const char*>(contents), totalSize);
    return totalSize;
}

// --- HTTP Client Logic ---
HttpResult HttpRequest(const string& url, const string& method = "GET",
                       const vector<string>& headers = {}, const string& body = "",
                       int delayMs = 0, bool noVerifySsl = false) {
    HttpResult result;

    if (delayMs > 0) {
        this_thread::sleep_for(chrono::milliseconds(delayMs));
    }

    CurlHandle curl;
    if (!curl.isValid()) return result;

    CURL* c = curl.get();
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, DEFAULT_TIMEOUT);  // FIX #6: DEFAULT_TIMEOUT is now long
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
    // FIX #8: Only disable SSL verification when explicitly requested
    if (noVerifySsl) {
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    curl_easy_setopt(c, CURLOPT_USERAGENT, "ZombieAPI-Concurrent/1.0");

    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, WriteBodyCallback);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &result.headers);

    if (!body.empty()) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    }

    struct curl_slist* rawHdrList = nullptr;
    for (const auto& h : headers) {
        rawHdrList = curl_slist_append(rawHdrList, h.c_str());
    }
    CurlSlistPtr hdrList(rawHdrList);
    if (hdrList) curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrList.get());

    CURLcode res = curl_easy_perform(c);
    if (res == CURLE_OK) {
        result.success = true;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &result.status);
        curl_easy_getinfo(c, CURLINFO_TOTAL_TIME, &result.timeSec);
        char* effUrl = nullptr;
        curl_easy_getinfo(c, CURLINFO_EFFECTIVE_URL, &effUrl);
        if (effUrl) result.effectiveUrl = effUrl;
        result.size = result.body.size();
    }

    return result;
}

// --- URL Helpers ---
string JoinUrl(const string& base, const string& path) {
    if (path.find("http://") == 0 || path.find("https://") == 0)
        return path;

    string result = base;
    if (!result.empty() && result.back() == '/') result.pop_back();

    // Extract the path portion of the base URL
    size_t schemeEnd = result.find("://");
    size_t pathStart = (schemeEnd != string::npos) ? result.find('/', schemeEnd + 3) : string::npos;

    string basePath = (pathStart != string::npos) ? result.substr(pathStart) : "";
    string basePrefix = (pathStart != string::npos) ? result.substr(0, pathStart) : result;

    // If the path starts with the same prefix as the base URL's path,
    // strip the duplicate prefix to avoid double-paths like /ws/ws/2/artist
    string cleanPath = path;
    if (!basePath.empty() && !cleanPath.empty() && cleanPath[0] == '/') {
        if (cleanPath.find(basePath) == 0) {
            cleanPath = cleanPath.substr(basePath.length());
            if (cleanPath.empty() || cleanPath[0] != '/') {
                cleanPath = "/" + cleanPath;
            }
        }
    }

    // Join basePrefix with cleanPath
    result = basePrefix;
    if (!cleanPath.empty() && cleanPath.front() != '/') result += '/';
    result += cleanPath;
    return result;
}

// --- CSV Output Support ---
// Escape a field for CSV output per RFC 4180:
// - If the field contains a comma, double quote, or newline, wrap it in double quotes
// - Any double quotes inside the field are escaped by doubling them
string CsvEscape(const string& field) {
    bool needsQuoting = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needsQuoting = true;
            break;
        }
    }
    if (!needsQuoting) return field;

    string escaped;
    escaped.reserve(field.size() + 2);
    escaped += '"';
    for (char c : field) {
        if (c == '"') escaped += "\"\"";  // Escape double quote by doubling
        else escaped += c;
    }
    escaped += '"';
    return escaped;
}

// Structured record for CSV export
struct CsvRecord {
    string url;
    long status;
    size_t size;
    bool isApi;
    string source;  // Which module discovered it (crawl, fuzz, passive-recon, etc.)
};

// --- Extraction Logic ---
static const regex RE_API_PATH(R"((["'`]?)(/api/[^"'`\s<>]{3,}))");
static const regex RE_ABS_API(R"((["'`]?)(https?://[^/\s"'`]+/api/[^\s"'`]+))");
     static const regex RE_GENERIC_PATH(R"((["'`]?)\s?(/[a-zA-Z0-9_\-/]{3,}))");

vector<string> ExtractEndpoints(const string& content, const string& baseUrl) {
    set<string> unique;

    auto begin = sregex_iterator(content.begin(), content.end(), RE_API_PATH);
    auto end = sregex_iterator();
    for (auto i = begin; i != end; ++i) {
        string match = (*i)[2].str();
        if (match.back() == '/') match.pop_back();
        unique.insert(JoinUrl(baseUrl, match));
    }

    begin = sregex_iterator(content.begin(), content.end(), RE_ABS_API);
    for (auto i = begin; i != end; ++i) {
        string match = (*i)[2].str();
        if (match.back() == '/') match.pop_back();
        unique.insert(match);
    }

    begin = sregex_iterator(content.begin(), content.end(), RE_GENERIC_PATH);
    for (auto i = begin; i != end; ++i) {
        string match = (*i)[2].str();
        if (match.back() == '/') match.pop_back();
        unique.insert(match);
    }

    return vector<string>(unique.begin(), unique.end());
}

// --- Crawler Support ---

// Extract host from a full URL (e.g., "https://api.example.com/path" -> "https://api.example.com")
string ExtractHost(const string& url) {
    size_t schemeEnd = url.find("://");
    if (schemeEnd == string::npos) return "";
    size_t hostStart = schemeEnd + 3;
    size_t pathStart = url.find('/', hostStart);
    if (pathStart == string::npos) return url;
    return url.substr(0, pathStart);
}

// Check if a link belongs to the same host (or is a relative path)
bool IsSameHost(const string& link, const string& baseHost) {
    if (link.empty()) return false;
    // Protocol-relative URL (starts with //) - belongs to a different host
    if (link[0] == '/' && link.size() > 1 && link[1] == '/') return false;
    // Relative path (starts with / but not //)
    if (link[0] == '/') return true;
    // Absolute URL - must have a scheme to compare hosts
    if (link.find("://") == string::npos) return false;
    return ExtractHost(link) == baseHost;
}

vector<string> ExtractLinks(const string& html, const string& baseHost) {
    static const regex linkRe(R"(href\s*=\s*["']([^"'#]+))", regex::icase);
    static const regex srcRe(R"(src\s*=\s*["']([^"'#]+))", regex::icase);

    set<string> urls;

    if (html.empty()) return vector<string>();

    for (sregex_iterator i(html.begin(), html.end(), linkRe); i != sregex_iterator(); ++i) {
        string link = (*i)[1];
        if (IsSameHost(link, baseHost)) {
            urls.insert(link);
        }
    }

    for (sregex_iterator i(html.begin(), html.end(), srcRe); i != sregex_iterator(); ++i) {
        string src = (*i)[1];
        if (IsSameHost(src, baseHost)) {
            urls.insert(src);
        }
    }

    return vector<string>(urls.begin(), urls.end());
}

// --- Concurrent Crawler Engine ---
struct CrawlTask {
    string url;
    int depth;
};

// --- API Detection ---

bool IsApiResponse(const HttpResult& result) {

    // Must not look like HTML
    if (result.body.find("<html") != string::npos ||
        result.body.find("<HTML") != string::npos ||
        result.body.find("<!DOCTYPE") != string::npos ||
        result.body.find("<body") != string::npos ||
        result.body.find("<div") != string::npos ||
        result.body.find("<script") != string::npos ||
        result.body.find("<style") != string::npos) {
        return false;
    }

    // Filter out common static file indicators in Content-Type
    if (result.headers.find("text/html") != string::npos ||
        result.headers.find("text/css") != string::npos ||
        result.headers.find("text/javascript") != string::npos ||
        result.headers.find("application/javascript") != string::npos ||
        result.headers.find("text/plain") != string::npos ||
        result.headers.find("image/") != string::npos ||
        result.headers.find("font/") != string::npos ||
        result.headers.find("video/") != string::npos ||
        result.headers.find("audio/") != string::npos ||
        result.headers.find("application/octet-stream") != string::npos) {
        return false;
    }

    // STRONG indicator: explicit JSON/XML Content-Type header
    if (result.headers.find("application/json") != string::npos ||
        result.headers.find("application/xml")  != string::npos ||
        result.headers.find("text/xml")         != string::npos ||
        result.headers.find("application/ld+json") != string::npos ||
        result.headers.find("application/hal+json") != string::npos ||
        result.headers.find("application/problem+json") != string::npos) {
        return true;
    }

    // WEAK fallback: body starts with { or [ and contains structured fields
    // This is only used when no Content-Type header is present
    string trimmed = result.body;
    size_t firstNonWs = trimmed.find_first_not_of(" \t\n\r");
    if (firstNonWs == string::npos) return false;
    trimmed.erase(0, firstNonWs);
    if (trimmed.empty()) return false;

    // Must start with JSON object or array
    if (trimmed[0] != '{' && trimmed[0] != '[') return false;

    // Must end with matching closing bracket
    string bodyCopy = result.body;
    char lastChar = bodyCopy.back();
    while (!bodyCopy.empty() && (lastChar == ' ' || lastChar == '\n' ||
           lastChar == '\r' || lastChar == '\t')) {
        bodyCopy.pop_back();
        if (!bodyCopy.empty()) lastChar = bodyCopy.back();
    }
    bool balanced = (trimmed[0] == '{' && lastChar == '}') ||
                    (trimmed[0] == '[' && lastChar == ']');
    if (!balanced) return false;

    // Must contain at least 2 structured field indicators (require multiple for confidence)
    int fieldCount = 0;
    if (result.body.find("\"id\"") != string::npos) fieldCount++;
    if (result.body.find("\"data\"") != string::npos) fieldCount++;
    if (result.body.find("\"results\"") != string::npos) fieldCount++;
    if (result.body.find("\"items\"") != string::npos) fieldCount++;
    if (result.body.find("\"error\"") != string::npos) fieldCount++;
    if (result.body.find("\"message\"") != string::npos) fieldCount++;
    if (result.body.find("\"status\"") != string::npos) fieldCount++;
    if (result.body.find("\"success\"") != string::npos) fieldCount++;
    if (result.body.find("\"type\"") != string::npos) fieldCount++;
    if (result.body.find("\"name\"") != string::npos) fieldCount++;
    if (result.body.find("\"value\"") != string::npos) fieldCount++;
    if (result.body.find("\"count\"") != string::npos) fieldCount++;

    return fieldCount >= 2;  // Require at least 2 indicators for confidence
}

// --- Common API Path Fuzzer ---
void FuzzCommonEndpoints(const string& baseUrl, int threads, int delayMs) {
    SafePrint("🎯 Fuzzing " + to_string(COMMON_API_PATHS.size()) +
              " common API paths...");

    ThreadPool pool(threads);
    mutex fuzzMutex;
    int found = 0;

    for (const auto& path : COMMON_API_PATHS) {
        pool.enqueue([baseUrl, path, delayMs, &fuzzMutex, &found]() {
            string url = JoinUrl(baseUrl, path);
            HttpResult res = HttpRequest(url, "GET", {}, "", delayMs);

            if (res.success && (res.status == 200 || res.status == 401 ||
                res.status == 403 || res.status == 405 || res.status == 429)) {
                if (IsApiResponse(res) || res.status == 401 || res.status == 403) {
                    SafePrint("🧟 Potential API: " + url + " (HTTP " +
                             to_string(res.status) + ")");
                    AddEndpoint(url);
                    {
                        lock_guard<mutex> lock(fuzzMutex);
                        found++;
                    }
                }
            }
        });
    }

    pool.waitAll();
    SafePrint("✅ Fuzzing complete. Potential APIs found: " + to_string(found));
}

// --- Concurrent Crawler ---
vector<HttpResult> CrawlConcurrent(const string& startUrl,
                                   int maxDepth,
                                   int threads,
                                   int delayMs)
{
    vector<HttpResult> allResults;
    mutex resultsMutex;

    unordered_set<string> visited;
    mutex visitedMutex;

    string host = startUrl;
    size_t schemeEnd = startUrl.find("://");
    if (schemeEnd != string::npos) {
        size_t hostEnd = startUrl.find("/", schemeEnd + 3);
        if (hostEnd != string::npos) {
            host = startUrl.substr(0, hostEnd);
        }
    }

    vector<CrawlTask> currentLayer;
    currentLayer.push_back({startUrl, 0});

    {
        lock_guard<mutex> lock(visitedMutex);
        visited.insert(startUrl);
    }

    SafePrint("🕷️  Starting crawl from: " + startUrl);

    for (int d = 0; d <= maxDepth; ++d) {
        if (currentLayer.empty()) {
            SafePrint("📍 Depth " + to_string(d) + ": No more URLs to crawl");
            break;
        }

        SafePrint("📍 Depth " + to_string(d) + ": Processing " +
                  to_string(currentLayer.size()) + " URLs");

        vector<HttpResult> layerResults;
        mutex layerMutex;
        vector<CrawlTask> nextLayer;
        mutex nextMutex;
        atomic<int> endpointsFound{0};
        atomic<int> apiDetected{0};

        {
            ThreadPool pool(threads);

            for (const auto& task : currentLayer) {
                pool.enqueue([task, host, delayMs,
                              &layerMutex, &layerResults,
                              &visitedMutex, &visited,
                              &nextMutex, &nextLayer,
                              maxDepth, &endpointsFound, &apiDetected]() mutable
                {
                    HttpResult res = HttpRequest(task.url, "GET", {}, "", delayMs);

                    {
                        lock_guard<mutex> lock(layerMutex);
                        if (res.success) layerResults.push_back(res);
                    }

                    if (res.success && !res.body.empty()) {
                        if (IsApiResponse(res)) {
                            apiDetected++;
                            SafePrint("🧟 API ENDPOINT DETECTED: " + task.url +
                                     " (Status: " + to_string(res.status) + ")");
                            AddEndpoint(task.url);
                        }

                        auto eps = ExtractEndpoints(res.body, res.effectiveUrl);
                        if (!eps.empty()) {
                            endpointsFound += eps.size();
                            SafePrint("🔗 Found " + to_string(eps.size()) +
                                     " endpoint references on: " + task.url);
                        }
                        for (const auto& ep : eps) {
                            AddEndpoint(ep);
                        }
                    }

                    if (res.success && task.depth < maxDepth) {
                        auto links = ExtractLinks(res.body, host);
                        for (const auto& link : links) {
                            string next = (link[0] == '/') ? host + link : link;
                            bool shouldVisit = false;
                            {
                                lock_guard<mutex> lock(visitedMutex);
                                if (visited.find(next) == visited.end()) {
                                    visited.insert(next);
                                    shouldVisit = true;
                                }
                            }
                            if (shouldVisit) {
                                lock_guard<mutex> lock(nextMutex);
                                nextLayer.push_back({next, task.depth + 1});
                            }
                        }
                    }
                });
            }
            // FIX #4: waitAll() called explicitly before pool goes out of scope
            pool.waitAll();
        }

        SafePrint("✅ Depth " + to_string(d) + " complete. " +
                  "Endpoints found: " + to_string(endpointsFound.load()) +
                  ", API responses detected: " + to_string(apiDetected.load()));

        {
            lock_guard<mutex> lock(resultsMutex);
            allResults.insert(allResults.end(),
                              layerResults.begin(),
                              layerResults.end());
        }

        currentLayer = std::move(nextLayer);
    }

    return allResults;
}

// =============================================================================
// HIDDEN / ZOMBIE API DISCOVERY
// =============================================================================

// ---------------------------------------------------------------------------
// BodyFingerprint – lightweight hash: length bucket + first-128-char prefix.
// Used by DiffFuzz to detect routes whose response deviates from a 404 baseline.
// ---------------------------------------------------------------------------
string BodyFingerprint(const string& body) {
    // Bucket by size (nearest 64 bytes) and use first 256 chars for better discrimination.
    size_t bucket = (body.size() / 64) * 64;
    string prefix = body.substr(0, min(body.size(), size_t(256)));
    return to_string(bucket) + "|" + prefix;
}

// ---------------------------------------------------------------------------
// ExtractFromSourceMap - parse a JS source map JSON and return every
// "sources" entry that looks like an API route.
// Source maps are goldmines: they contain the pre-bundled file paths that
// sometimes include internal service names and undocumented route handlers.
// ---------------------------------------------------------------------------
vector<string> ExtractFromSourceMap(const string& mapJson) {
    vector<string> found;
    // Match "sources":[...] array entries
    static const regex srcArray(R"("sources"\s*:\s*\[([^\]]*)\])");
    // Named delimiter avoids ") clash with the inner quote in the pattern
    static const regex srcEntry(R"rx("([^"]+)")rx");

    smatch arrMatch;
    // regex_search requires a non-const string lvalue for match storage
    string mapJsonCopy = mapJson;
    if (!regex_search(mapJsonCopy, arrMatch, srcArray)) return found;

    string arr = arrMatch[1].str();
    auto begin = sregex_iterator(arr.begin(), arr.end(), srcEntry);
    for (auto it = begin; it != sregex_iterator(); ++it) {
        string entry = (*it)[1].str();
        // Keep entries that look like route/handler paths
        if (entry.find("/api/")     != string::npos ||
            entry.find("route")     != string::npos ||
            entry.find("controller")!= string::npos ||
            entry.find("handler")   != string::npos ||
            entry.find("endpoint")  != string::npos) {
            found.push_back(entry);
        }
    }
    return found;
}

// ---------------------------------------------------------------------------
// ExtractFromOpenApiSpec – pull every path key from an OpenAPI / Swagger body.
// Handles both JSON ("/paths": {...}) and YAML (^  /foo:) surface forms.
// ---------------------------------------------------------------------------
vector<string> ExtractFromOpenApiSpec(const string& specBody,
                                                 const string& baseUrl) {
    vector<string> found;

    // Named delimiter avoids ") clash with the closing quote in the pattern
    static const regex jsonPath(R"rx("(/[a-zA-Z0-9_/\-{}]+)"\s*:)rx");
    // YAML: lines starting with "  /path:"
    static const regex yamlPath(R"(^\s{0,4}(/[a-zA-Z0-9_/\-{}]+)\s*:)", regex::multiline);

    set<string> unique;

    // Explicit array avoids initializer_list type-deduction failure for regex
    const regex* reList[] = {&jsonPath, &yamlPath};
    for (const auto* rep : reList) {
        auto begin = sregex_iterator(specBody.begin(), specBody.end(), *rep);
        for (auto it = begin; it != sregex_iterator(); ++it) {
            string path = (*it)[1].str();
            // Skip template parameters (e.g., /users/{user_id}) — handled separately
            if (path.find('{') == string::npos)
                unique.insert(JoinUrl(baseUrl, path));
        }
    }

    found.assign(unique.begin(), unique.end());
    return found;
}

// ---------------------------------------------------------------------------
// ExpandAndProbeTemplatePaths — extract template paths (e.g., /served/{years})
// from the spec, substitute smart parameter values, probe with HTTP, and
// return only the working endpoints.
// ---------------------------------------------------------------------------
vector<string> ExpandAndProbeTemplatePaths(const string& specBody, const string& baseUrl,
                                            int delayMs, bool noVerifySsl) {
    vector<string> found;
    static const regex jsonPath(R"rx("(/[a-zA-Z0-9_/\-{}]+)"\s*:)rx");
    static const regex yamlPath(R"(^\s{0,4}(/[a-zA-Z0-9_/\-{}]+)\s*:)", regex::multiline);
    static const regex tmplParam(R"(\{(\w+)\})");

    set<string> expanded;

    const regex* reList[] = {&jsonPath, &yamlPath};
    for (const auto* rep : reList) {
        auto begin = sregex_iterator(specBody.begin(), specBody.end(), *rep);
        for (auto it = begin; it != sregex_iterator(); ++it) {
            string path = (*it)[1].str();
            if (path.find('{') == string::npos) continue;

            string resolved = path;
            smatch pm;
            while (regex_search(resolved, pm, tmplParam)) {
                string pname = pm[1].str();
                string sub = "1";
                if (pname == "year" || pname == "years") sub = "2024";
                resolved.replace(pm.position(0), pm.length(0), sub);
            }
            if (resolved != path)
                expanded.insert(JoinUrl(baseUrl, resolved));
        }
    }

    for (const auto& url : expanded) {
        HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
        if (r.success && r.status >= 200 && r.status < 500 && r.status != 404 && r.status != 410) {
            string classify = "NORMAL";
            if (url.find("/v0") != string::npos || url.find("/old") != string::npos)
                classify = "ZOMBIE";
            SafePrint("   🧟 [" + classify + "] " + url + " (template expansion)");
            found.push_back(url);
        }
    }
    return found;
}

// ---------------------------------------------------------------------------
// PassiveRecon - mine JS bundles, source maps, OpenAPI/Swagger specs,
// robots.txt, and sitemap.xml for undocumented or retired routes.
//
// Strategy:
//   1. Fetch robots.txt - Disallow: entries are often hidden endpoints.
//   2. Fetch sitemap.xml - <loc> entries reveal page/API structure.
//   3. Walk <script src=...> tags from the root page body (passed via g_endpoints
//      which is already populated by the crawl).  For each .js URL:
//        a. Fetch the JS and extract inline /api/... strings.
//        b. Try <jsUrl>.map - if the source map exists, mine its "sources".
//   4. Probe well-known OpenAPI / Swagger spec URLs and extract all paths.
// ---------------------------------------------------------------------------
void PassiveRecon(const string& baseUrl, int threads, int delayMs, bool noVerifySsl) {
    SafePrint("\n🔎 [PassiveRecon] Starting passive hidden-endpoint discovery on: " + baseUrl);

    ThreadPool pool(threads);
    mutex reconMutex;
    int totalFound = 0;

    // ---- 1. robots.txt ----
    pool.enqueue([&, baseUrl, delayMs, noVerifySsl]() {
        string url = JoinUrl(baseUrl, "/robots.txt");
        HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
        if (!r.success || r.status != 200) return;

        SafePrint("🤖 [PassiveRecon] Parsing robots.txt");
        // Capture both Disallow and Allow directives — both may reference hidden routes
        static const regex robotDir(R"((?:Disallow|Allow)\s*:\s*(/[^\s\*]+))", regex::icase);
        auto begin = sregex_iterator(r.body.begin(), r.body.end(), robotDir);
        int cnt = 0;
        for (auto it = begin; it != sregex_iterator(); ++it) {
            string path = (*it)[1].str();
            string full = JoinUrl(baseUrl, path);
            SafePrint("   🧟 [robots.txt] Hidden path: " + full);
            AddEndpoint(full);
            cnt++;
        }
        lock_guard<mutex> lk(reconMutex);
        totalFound += cnt;
    });

    // ---- 2. sitemap.xml (and sitemap_index) ----
    pool.enqueue([&, baseUrl, delayMs, noVerifySsl]() {
        for (const auto& smap : {"/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"}) {
            string url = JoinUrl(baseUrl, smap);
            HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
            if (!r.success || r.status != 200) continue;

            SafePrint("🗺️  [PassiveRecon] Parsing " + url);
            static const regex locRe(R"(<loc>\s*(https?://[^<]+)\s*</loc>)");
            auto begin = sregex_iterator(r.body.begin(), r.body.end(), locRe);
            int cnt = 0;
            for (auto it = begin; it != sregex_iterator(); ++it) {
                string loc = (*it)[1].str();
                // Flag entries that look like API routes
                if (loc.find("/api/") != string::npos ||
                    loc.find("/v1/")  != string::npos ||
                    loc.find("/v2/")  != string::npos) {
                    SafePrint("   🧟 [sitemap] API path in sitemap: " + loc);
                    AddEndpoint(loc);
                    cnt++;
                }
            }
            lock_guard<mutex> lk(reconMutex);
            totalFound += cnt;
        }
    });

    // ---- 3. OpenAPI / Swagger spec probing ----
    const vector<string> specPaths = {
        "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/swagger.yml",
        "/api/swagger.json", "/api/swagger.yaml", "/api/swagger.yml", "/api/openapi.json", "/app/openapi.json",
        "/api-docs", "/api/api-docs", "/v1/api-docs", "/v2/api-docs",
        "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v3/swagger.json",
        "/api/v1/openapi.json", "/api/v2/openapi.json", "/docs/openapi.json"
    };

    for (const auto& specPath : specPaths) {
        pool.enqueue([&, baseUrl, specPath, delayMs, noVerifySsl]() {
            string url = JoinUrl(baseUrl, specPath);
            HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
            if (!r.success || r.status != 200 || r.body.size() < 20) return;

            // Quick smell-test: must contain "paths" or "swagger"/"openapi"
            bool looksLikeSpec = (r.body.find("\"paths\"") != string::npos ||
                                  r.body.find("paths:")    != string::npos ||
                                  r.body.find("\"swagger\"")!= string::npos ||
                                  r.body.find("\"openapi\"")!= string::npos);
            if (!looksLikeSpec) return;

            SafePrint("📄 [PassiveRecon] OpenAPI/Swagger spec found: " + url);
            auto paths = ExtractFromOpenApiSpec(r.body, baseUrl);
            int cnt = 0;
            for (const auto& p : paths) {
                // Classification based on path patterns  
                string classify = "NORMAL";
                
                // Check for deprecated indicators in path name or version
                if (p.find("/v0") != string::npos || 
                    p.find("/v1/") != string::npos ||  // Old versions likely deprecated
                    p.find("old") != string::npos || 
                    p.find("legacy") != string::npos ||
                    p.find("deprecated") != string::npos) {
                    classify = "ZOMBIE";  
                }
                
                SafePrint("   🧟 [" + classify + "] " + p);
                AddEndpoint(p);
                cnt++;
            }
            lock_guard<mutex> lk(reconMutex);
            totalFound += cnt;
        });
    }

    // ---- 3b. Expand and probe template paths from the spec ---- 
    // (Runs after the spec is fetched above; re-fetches the spec if needed)
    for (const auto& specPath : specPaths) {
        pool.enqueue([&, baseUrl, specPath, delayMs, noVerifySsl]() {
            string url = JoinUrl(baseUrl, specPath);
            HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
            if (!r.success || r.status != 200 || r.body.size() < 20) return;
            bool looksLikeSpec = (r.body.find("\"paths\"") != string::npos ||
                                  r.body.find("paths:")    != string::npos ||
                                  r.body.find("\"swagger\"")!= string::npos ||
                                  r.body.find("\"openapi\"")!= string::npos);
            if (!looksLikeSpec) return;
            auto tmplPaths = ExpandAndProbeTemplatePaths(r.body, baseUrl, delayMs, noVerifySsl);
            int cnt = 0;
            for (const auto& p : tmplPaths) {
                string classify = "NORMAL";
                if (p.find("/v0") != string::npos || p.find("/old") != string::npos)
                    classify = "ZOMBIE";
                SafePrint("   🧟 [" + classify + "] " + p);
                AddEndpoint(p);
                cnt++;
            }
            lock_guard<mutex> lk(reconMutex);
            totalFound += cnt;
        });
    }

    // ---- 3c. Probe common API documentation pages ----
    const vector<string> docPaths = {
        "/redoc", "/docs", "/swagger", "/swagger-ui", "/rapidoc",
        "/api-docs", "/api/documentation", "/documentation"
    };
    for (const auto& docPath : docPaths) {
        pool.enqueue([&, baseUrl, docPath, delayMs, noVerifySsl]() {
            string url = JoinUrl(baseUrl, docPath);
            HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
            if (!r.success || r.status != 200) return;
            // Only flag HTML doc pages; raw API endpoints handled elsewhere
            if (r.body.find("<!DOCTYPE html") != string::npos ||
                r.body.find("<html") != string::npos ||
                r.body.find("ReDoc") != string::npos ||
                r.body.find("Swagger") != string::npos) {
                SafePrint("   📖 [doc-page] API documentation: " + url);
                AddEndpoint(url);
                lock_guard<mutex> lk(reconMutex);
                totalFound++;
            }
        });
    }

    // ---- 4. JS bundle + source map mining ----
    // Collect script URLs already discovered in g_endpoints or extract from root page
    vector<string> jsUrls;
    {
        lock_guard<mutex> lk(g_endpointsMutex);
        for (const auto& ep : g_endpoints) {
            if (ep.size() > 3 &&
                ep.substr(ep.size() - 3) == ".js") {
                jsUrls.push_back(ep);
            }
        }
    }

    // Also probe common bundle locations
    for (const auto& staticPath : {"/static/js/main.js", "/assets/index.js",
                                    "/app.js", "/bundle.js", "/dist/app.js",
                                    "/js/app.js", "/public/app.js"}) {
        jsUrls.push_back(JoinUrl(baseUrl, staticPath));
    }

    for (const auto& jsUrl : jsUrls) {
        pool.enqueue([&, jsUrl, delayMs, noVerifySsl]() {
            HttpResult r = HttpRequest(jsUrl, "GET", {}, "", delayMs, noVerifySsl);
            if (!r.success || r.status != 200) return;

            // a. Extract inline /api/... strings from JS body
            auto eps = ExtractEndpoints(r.body, baseUrl);
            if (!eps.empty()) {
                SafePrint("📦 [PassiveRecon] JS bundle " + jsUrl +
                          " yielded " + to_string(eps.size()) + " endpoint(s)");
                for (const auto& ep : eps) {
                    SafePrint("   🧟 [js-bundle] " + ep);
                    AddEndpoint(ep);
                }
                lock_guard<mutex> lk(reconMutex);
                totalFound += (int)eps.size();
            }

            // b. Try the source map (.map)
            string mapUrl = jsUrl + ".map";
            HttpResult mapR = HttpRequest(mapUrl, "GET", {}, "", delayMs, noVerifySsl);
            if (mapR.success && mapR.status == 200 && !mapR.body.empty()) {
                SafePrint("🗺️  [PassiveRecon] Source map found: " + mapUrl);
                auto sources = ExtractFromSourceMap(mapR.body);
                for (const auto& src : sources) {
                    SafePrint("   🧟 [source-map] Handler/route reference: " + src);
                    // Source map entries are file paths, not URLs — store as annotation
                    lock_guard<mutex> lk(g_endpointsMutex);
                    g_endpoints.insert("[source-map] " + src);
                }
                lock_guard<mutex> lk(reconMutex);
                totalFound += (int)sources.size();
            }
        });
    }

    pool.waitAll();
    SafePrint("✅ [PassiveRecon] Complete. Hidden references discovered: " +
              to_string(totalFound));
}

// ---------------------------------------------------------------------------
// HeaderProbe - re-request each discovered endpoint with manipulated headers
// that API gateways and reverse proxies commonly forward to upstream services.
// Routes that respond differently under these headers are likely shadow/internal
// endpoints that the gateway normally hides from public clients.
//
// Probed headers:
//   Host: internal.service / localhost
//   X-Forwarded-For: 127.0.0.1
//   X-Original-URL / X-Rewrite-URL: path overrides (gateway bypass)
//   X-Custom-IP-Authorization: 127.0.0.1
//   X-HTTP-Method-Override: (verb spoofing via header)
// ---------------------------------------------------------------------------
void HeaderProbe(const vector<string>& endpoints,
                 int threads, int delayMs, bool noVerifySsl) {
    SafePrint("\n👻 [HeaderProbe] Probing " + to_string(endpoints.size()) +
              " endpoints with manipulated routing headers...");

    // Baseline: fingerprint a guaranteed-miss URL to calibrate "normal 404"
    // We just capture status; body diff is handled by DiffFuzz.

    mutex probeMutex;
    int shadowsFound = 0;
    ThreadPool pool(threads);

    // Header sets to try
    struct HeaderSet {
        string label;
        vector<string> headers;
    };

    const vector<HeaderSet> headerSets = {
        {
            "X-Forwarded-For: 127.0.0.1",
            {"X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1"}
        },
        {
            "X-Original-URL override",
            {"X-Original-URL: /admin", "X-Rewrite-URL: /admin"}
        },
        {
            "Internal Host header",
            {"Host: localhost", "X-Custom-IP-Authorization: 127.0.0.1"}
        },
        {
            "Bypass via method override",
            {"X-HTTP-Method-Override: GET", "X-Method-Override: GET"}
        },
        {
            "Internal service simulation",
            {"X-Forwarded-Host: internal.api", "X-Forwarded-Proto: http",
             "X-Forwarded-For: 10.0.0.1"}
        }
    };

    for (const auto& ep : endpoints) {
        // Get baseline status for this endpoint
        HttpResult baseline = HttpRequest(ep, "GET", {}, "", delayMs, noVerifySsl);
        if (!baseline.success) continue;

        for (const auto& hs : headerSets) {
            pool.enqueue([ep, hs, baseline, delayMs, noVerifySsl,
                          &probeMutex, &shadowsFound]() {
                HttpResult probed = HttpRequest(ep, "GET", hs.headers, "", delayMs, noVerifySsl);
                if (!probed.success) return;

                bool statusDiff  = (probed.status != baseline.status);
                bool sizeDiff    = (probed.size > baseline.size + 64 ||
                                   (baseline.size > 64 && probed.size < baseline.size / 2));

                if (statusDiff || sizeDiff) {
                    
                    // Classify shadow route detection  
                    string classify = "SUSPECT";  // Shadow routes are inherently suspicious
                    int score = 50;
                    
                    if (probed.status == 401 || probed.status == 403) {
                        score += 20;  // Auth-gated shadow routes
                    } else if (probed.status >= 200 && probed.status < 300) {
                        score += 30;  // Fully accessible shadow = critical
                    }
                    
                    // Check header type for severity
                    if (hs.label.find("X-Original-URL") != string::npos ||
                         hs.label.find("Host: localhost") != string::npos) {
                        score += 15;  // Gateway bypass is high risk
                    }
                    
                    if (score >= 60) classify = "ZOMBIE";
                    
                    stringstream ss;
                    ss << "   👻 [" + classify + "] SHADOW ROUTE DETECTED: " << ep << "\n"
                       << "      Header set : " << hs.label << "\n"
                       << "      Baseline   : HTTP " << baseline.status
                       << " / " << baseline.size << " bytes\n"
                       << "      Probed     : HTTP " << probed.status
                       << " / " << probed.size << " bytes";
                    SafePrint(ss.str());
                    AddEndpoint(ep + " [shadow via: " + hs.label + "]");
                    lock_guard<mutex> lk(probeMutex);
                    shadowsFound++;
                }
            });
        }
    }

    pool.waitAll();
    SafePrint("✅ [HeaderProbe] Complete. Shadow routes detected: " +
              to_string(shadowsFound));
}

// ---------------------------------------------------------------------------
// ChangelogHunt - probe debug, actuator, and .well-known paths that commonly
// surface internal, deprecated, or end-of-life endpoints.
//
// Targets include:
//   Spring Boot Actuator  (/actuator/**, /actuator/mappings leaks ALL routes)
//   Django debug          (/_debug, /debug, /api/__debug__)
//   Laravel telescope     (/telescope/api/requests)
//   .well-known           (/.well-known/security.txt sometimes lists APIs)
//   Changelog / CHANGELOG (retire-notice pages often reference old endpoints)
//   Express internals     (/api-explorer, /explorer, /console)
// ---------------------------------------------------------------------------
void ChangelogHunt(const string& baseUrl, int threads, int delayMs, bool noVerifySsl) {
    SafePrint("\n📜 [ChangelogHunt] Probing debug/actuator/well-known paths on: " + baseUrl);

    // Paths known to expose internal or retired endpoints
    const vector<string> huntPaths = {
        // Spring Boot Actuator (goldmine — /mappings lists every registered route)
        "/actuator", "/actuator/mappings", "/actuator/beans", "/actuator/env",
        "/actuator/info", "/actuator/health", "/actuator/routes",
        "/manage/actuator", "/management/actuator/mappings",
        // Django / DRF
        "/_debug", "/debug", "/api/__debug__", "/api/debug",
        "/__debug__/", "/silk/",                // django-silk profiler
        // Laravel
        "/telescope/api/requests", "/horizon/api/jobs",
        // Express / Node
        "/api-explorer", "/explorer", "/console", "/_api",
        // Generic developer leftovers
        "/changelog", "/CHANGELOG", "/CHANGELOG.md",
        "/version", "/build-info", "/build_info", "/_version",
        "/api/version", "/api/status", "/api/health", "/api/ping",
        "/api/info", "/api/meta", "/api/schema",
        // .well-known
        "/.well-known/security.txt", "/.well-known/api-catalog",
        "/.well-known/openid-configuration",
        // Swagger UI residue (sometimes left enabled in prod)
        "/swagger-ui.html", "/swagger-ui/", "/api/swagger-ui.html",
        "/redoc", "/api/redoc",
        // Internal monitoring
        "/metrics", "/prometheus", "/stats", "/healthz", "/readyz",
        // Old versioned endpoints that may still respond
        "/api/v0", "/api/v1_old", "/api/beta", "/api/internal",
        "/internal/api", "/private/api", "/hidden/api"
    };

    ThreadPool pool(threads);
    mutex huntMutex;
    int found = 0;

    for (const auto& path : huntPaths) {
        pool.enqueue([&, baseUrl, path, delayMs, noVerifySsl]() {
            string url = JoinUrl(baseUrl, path);
            HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);

            // 200/206 = live,  401/403 = exists but auth-gated (still a zombie!),
            // 405 = method not allowed (endpoint exists), 301/302 = redirect worth noting
            if (r.success && (r.status == 200 || r.status == 206 ||
                              r.status == 401 || r.status == 403 ||
                              r.status == 405 || r.status == 301 || r.status == 302)) {
                
                // Classify endpoint based on path and response characteristics
                string classify = "NORMAL";
                int score = 40;  // Base score for being a debug/internal path
                
                if (r.status == 401 || r.status == 403) {
                    score += 25;  // Auth-gated internal paths are highly suspicious
                } else if (r.status == 200) {
                    score += 15;  // Open debug endpoints are critical issues
                } else if (r.status == 301 || r.status == 302) {
                    score += 10;  // Redirects may leak internal structure
                }
                
                // Check path patterns
                if (path.find("v0") != string::npos || 
                    path.find("legacy") != string::npos ||
                    path.find("_old") != string::npos) {
                    score += 25;
                } else if (path.find("debug") != string::npos ||
                          path.find("internal") != string::npos ||
                          path.find("_hidden") != string::npos) {
                    score += 15;  
                } else if (path.find("/v1/") != string::npos ||  // Old versions
                          path.find("/beta") != string::npos) {
                    score += 10;
                }
                
                if (score >= 60) classify = "ZOMBIE";
                
                string tag = "";
                if (r.status == 401 || r.status == 403) {
                    tag += " [auth-gated]";  
                } else if (r.status == 301 || r.status == 302) {
                    tag += " [redirect]";
                }
                
                SafePrint("   📜 [" + classify + "] " + url + 
                          " → HTTP " + to_string(r.status) + tag);
                AddEndpoint(url);

                // Special case: /actuator/mappings returns a JSON list of all routes
                if (path == "/actuator/mappings" && r.status == 200) {
                    SafePrint("   🚨 [ChangelogHunt] /actuator/mappings is OPEN — "
                              "extracting all registered routes!");
                    auto eps = ExtractEndpoints(r.body, baseUrl);
                    for (const auto& ep : eps) {
                        SafePrint("     🧟 [actuator] Route: " + ep);
                        AddEndpoint(ep);
                    }
                    // Also mine raw path strings from the JSON
                    // Named delimiter avoids ") clash with closing quote in pattern
                    static const regex actPath(R"rx("(/[a-zA-Z0-9_/\-{}\*]+)")rx");
                    auto begin = sregex_iterator(r.body.begin(), r.body.end(), actPath);
                    for (auto it = begin; it != sregex_iterator(); ++it) {
                        string p = (*it)[1].str();
                        if (p.size() > 2) AddEndpoint(JoinUrl(baseUrl, p));
                    }
                }

                lock_guard<mutex> lk(huntMutex);
                found++;
            }
        });
    }

    pool.waitAll();
    SafePrint("✅ [ChangelogHunt] Complete. Debug/internal paths responded: " +
              to_string(found));
}

// Generate random string for fuzzing
//
string GenerateRandomString(size_t length = 6) {
    static const string charset =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    static thread_local mt19937 rng(random_device{}());
    uniform_int_distribution<> dist(0, charset.size() - 1);

    string result;
    for (size_t i = 0; i < length; i++) {
        result += charset[dist(rng)];
    }
    return result;
}

// ---------------------------------------------------------------------------
// DiffFuzz - baseline-diff fuzzing for hidden endpoints.
//
// Algorithm:
//   1. Establish a "known-404" fingerprint by fetching a UUID-named path that
//      cannot plausibly exist (body size + first 128 chars).
//   2. Probe every path in the wordlist (or COMMON_API_PATHS if no wordlist).
//   3. Any response whose fingerprint diverges from the 404 baseline AND whose
//      status is not 404/410 is flagged as a potential hidden endpoint.
//
// This catches endpoints that return 200 with a custom "not found" HTML page
// (common in SPAs) where simple status-code checks would miss them, as well as
// endpoints behind a WAF that always returns 403 except for specific paths.
// ---------------------------------------------------------------------------
void DiffFuzz(const string& baseUrl,
              const vector<string>& paths,
              int threads, int delayMs, bool noVerifySsl) {

    // Use COMMON_API_PATHS as fallback if caller passes nothing
    const vector<string>& probePaths =
        paths.empty() ? COMMON_API_PATHS : paths;

    SafePrint("\n🔬 [DiffFuzz] Establishing 404 baseline for: " + baseUrl);

    // Step 1: baseline fingerprint
    string sentinel = JoinUrl(baseUrl, "/____zombieapi_does_not_exist_9f3a7b____");
    HttpResult base404 = HttpRequest(sentinel, "GET", {}, "", delayMs, noVerifySsl);
    if (!base404.success) {
        SafePrint("⚠️  [DiffFuzz] Could not reach target for baseline — skipping.");
        return;
    }
    string baseFingerprint = BodyFingerprint(base404.body);
    long   baseStatus = base404.status;

    SafePrint("   Baseline: HTTP " + to_string(baseStatus) +
              " / " + to_string(base404.size) + " bytes");
    SafePrint("🔬 [DiffFuzz] Probing " + to_string(probePaths.size()) +
              " paths for fingerprint deviation...");

    ThreadPool pool(threads);
    mutex diffMutex;
    int hits = 0;

    for (const auto& path : probePaths) {
        pool.enqueue([&, baseUrl, path, baseFingerprint, baseStatus,
                      delayMs, noVerifySsl]() {
            string url = JoinUrl(baseUrl, path);
            HttpResult r = HttpRequest(url, "GET", {}, "", delayMs, noVerifySsl);
            if (!r.success) return;

            // Skip guaranteed misses
            if (r.status == 404 || r.status == 410) return;

            string fp = BodyFingerprint(r.body);
            bool statusDeviation = (r.status != baseStatus);
            bool bodyDeviation   = (fp != baseFingerprint);

            if (statusDeviation || bodyDeviation) {
                
                // Classify hidden endpoint from DiffFuzz  
                string classify = "NORMAL";
                int score = 65;  // Hidden by nature of deviating from 404
                
                if (r.status == 200 || r.status == 201 || r.status == 204) {
                    score += 15;  // Success codes on hidden paths
                    classify = "ZOMBIE";
                } else if (r.status == 301 || r.status == 302) {  
                    score += 10;
                } else if (r.status == 401 || r.status == 403) {
                    score += 5;  // Auth-gated hidden endpoint
                }
                
                // Check path patterns for versioning or suspicious names
                if (path.find("/v0") != string::npos || 
                    regex_search(path, regex(R"((/v[0-9]+)(/|$))"))) {
                    score += 15;
                    classify = "ZOMBIE";
                }
                
                if (classify == "NORMAL") classify = "HIDDEN";  // Label normal hidden endpoints
                
                stringstream ss;
                ss << "   🔬 [" + classify + "] Hidden endpoint: " << url << "\n"
                   << "      Status  : " << baseStatus << " → " << r.status
                   << (statusDeviation ? " ⚠️" : "") << "\n"
                   << "      Body fp : " << (bodyDeviation ? "DIFFERS" : "same");
                SafePrint(ss.str());
                AddEndpoint(url);
                lock_guard<mutex> lk(diffMutex);
                hits++;
            }
        });
    }

    pool.waitAll();
    SafePrint("✅ [DiffFuzz] Complete. Deviating (hidden) paths found: " +
              to_string(hits));
}

// ---------------------------------------------------------------------------
// RandomizedFuzz - enhanced endpoint discovery with multi-method probing,
// recursive expansion, header manipulation, and confidence scoring
// ---------------------------------------------------------------------------

// Confidence score calculation for endpoint detection
int CalculateConfidenceScore(const HttpResult& result) {
    int score = 0;

    // Status code scoring (0-50 points)
    if (result.status == 200) score += 50;
    else if (result.status == 201) score += 45;
    else if (result.status == 204) score += 40;
    else if (result.status == 301 || result.status == 302) score += 30;
    else if (result.status == 401 || result.status == 403) score += 35;  // Auth-gated = real endpoint
    else if (result.status == 405) score += 5;  // Method not allowed = parent exists, but not a real endpoint
    else if (result.status == 429) score += 20;  // Rate limited = endpoint likely exists
    else if (result.status >= 200 && result.status < 300) score += 40;
    else score += 10;

    // Content-Type scoring (0-30 points)
    if (result.headers.find("application/json") != string::npos) score += 30;
    else if (result.headers.find("application/xml") != string::npos) score += 25;
    else if (result.headers.find("text/xml") != string::npos) score += 25;
    else if (result.headers.find("application/ld+json") != string::npos) score += 30;
    else score += 5;

    // Response size scoring (0-20 points)
    // Reject very small (likely errors) and very large (likely static files)
    if (result.body.size() < 10) score -= 20;
    else if (result.body.size() < 50) score += 5;
    else if (result.body.size() < 10000) score += 20;  // Sweet spot for API responses
    else if (result.body.size() < 100000) score += 15;
    else score += 5;  // Very large, might be static file

    return score;
}

// Check if a status code indicates a real endpoint exists
bool IsValidEndpointStatus(long status) {
    // Accept: 2xx (success), 3xx (redirect), 401/403 (auth), 429 (rate limit)
    // Exclude 405 - it means the parent resource exists but the specific sub-path doesn't
    return (status >= 200 && status < 300) ||
           (status >= 300 && status < 400) ||
           status == 401 || status == 403 ||
           status == 429;
}

// Check if response body contains only error fields (not actual data)
bool IsErrorOnlyResponse(const string& body) {
    // Common error-only response patterns
    if (body.find("\"detail\"") != string::npos ||
        body.find("\"error\"") != string::npos ||
        body.find("\"message\"") != string::npos) {
        // Count data fields vs error fields
        int dataFields = 0;
        if (body.find("\"id\"") != string::npos) dataFields++;
        if (body.find("\"data\"") != string::npos) dataFields++;
        if (body.find("\"results\"") != string::npos) dataFields++;
        if (body.find("\"items\"") != string::npos) dataFields++;
        if (body.find("\"name\"") != string::npos) dataFields++;
        if (body.find("\"value\"") != string::npos) dataFields++;

        // If response is very small and has no data fields, it's likely just an error
        if (body.size() < 100 && dataFields == 0) {
            return true;
        }
    }
    return false;
}

// Recursive expansion: try common sub-paths after finding an endpoint
vector<string> GenerateSubPaths(const string& basePath) {
    vector<string> subPaths;
    vector<string> suffixes = {
        "/1", "/me", "/search", "/list", "/all", "/export", "/import",
        "/create", "/update", "/delete", "/status", "/info", "/config",
        "/admin", "/debug", "/test", "/demo", "/sample", "/example",
        "/active", "/enabled", "/disabled", "/count", "/total", "/summary",
        "/details", "/full", "/minimal", "/basic", "/advanced", "/raw",
        "/json", "/xml", "/csv", "/download", "/upload", "/view"
    };

    for (const auto& suffix : suffixes) {
        subPaths.push_back(basePath + suffix);
    }

    // Also try path parameters like /{id}
    for (int i = 1; i <= 5; i++) {
        subPaths.push_back(basePath + "/" + to_string(i));
    }

    return subPaths;
}

void ProbeSubPaths(const string& baseUrl, const vector<string>& endpoints,
                    int threads, int delayMs, bool noVerifySsl)
{
    (void)baseUrl;
    SafePrint("\n🔍 [ProbeSubPaths] Probing sub-paths on " +
              to_string(endpoints.size()) + " discovered endpoints...");

    mutex probeMutex;
    int found = 0;
    ThreadPool pool(threads);

    for (const auto& ep : endpoints) {
        pool.enqueue([ep, delayMs, noVerifySsl, &probeMutex, &found]() {
            // Fetch the endpoint to extract actual item IDs from the response
            HttpResult collection = HttpRequest(ep, "GET", {}, "", delayMs, noVerifySsl);
            vector<string> itemIds;
            if (collection.success && collection.status == 200 && !collection.body.empty()) {
                string body = collection.body;
                if (body.size() > 10000) body = body.substr(0, 10000);
                // Extract integer IDs from common fields
                static const regex idRe(R"xx("(?:id|user_id|product_id|order_id|file_id|log_id|book_id|movie_id|recipe_id)"\s*:\s*(\d+))xx");
                smatch m;
                string::const_iterator searchStart = body.cbegin();
                while (regex_search(searchStart, body.cend(), m, idRe)) {
                    itemIds.push_back(m[1].str());
                    searchStart = m.suffix().first;
                }
                // Also extract string IDs (e.g., "order_id":"ORD-1")
                static const regex strIdRe(R"zz("(?:id|order_id|user_id|product_id|file_id|log_id)"\s*:\s*"([^"]+)")zz");
                searchStart = body.cbegin();
                while (regex_search(searchStart, body.cend(), m, strIdRe)) {
                    itemIds.push_back(m[1].str());
                    searchStart = m.suffix().first;
                }
            }

            // Deduplicate IDs
            sort(itemIds.begin(), itemIds.end());
            itemIds.erase(unique(itemIds.begin(), itemIds.end()), itemIds.end());

            auto subPaths = GenerateSubPaths(ep);
            // Generate ID sub-paths from extracted IDs
            vector<string> idPaths;
            for (const auto& id : itemIds) {
                idPaths.push_back(ep + "/" + id);
            }

            // Probe named suffixes (skip numeric IDs handled separately)
            for (const auto& subPath : subPaths) {
                bool isNumericId = false;
                for (int i = 1; i <= 5; i++) {
                    if (subPath == ep + "/" + to_string(i)) {
                        isNumericId = true;
                        break;
                    }
                }
                if (isNumericId) continue;

                HttpResult r = HttpRequest(subPath, "GET", {}, "", delayMs, noVerifySsl);
                if (!r.success) continue;
                if (r.status != 404 && r.status != 410 && r.status != 422 && r.status != 429 && IsApiResponse(r)) {
                    AddEndpoint(subPath);
                    {
                        lock_guard<mutex> lk(probeMutex);
                        found++;
                    }
                    SafePrint("   ➕ " + subPath + " (HTTP " + to_string(r.status) + ")");
                }
            }

            // Probe extracted item IDs
            for (const auto& idPath : idPaths) {
                HttpResult r = HttpRequest(idPath, "GET", {}, "", delayMs, noVerifySsl);
                if (!r.success) continue;
                if (r.status != 404 && r.status != 410 && r.status != 422 && r.status != 429 && IsApiResponse(r)) {
                    AddEndpoint(idPath);
                    {
                        lock_guard<mutex> lk(probeMutex);
                        found++;
                    }
                    SafePrint("   ➕ " + idPath + " (HTTP " + to_string(r.status) + ")");
                }
            }
        });
    }

    pool.waitAll();
    SafePrint("✅ [ProbeSubPaths] Complete. New endpoints discovered: " +
              to_string(found));
}

void RandomizedFuzz(const string& baseUrl,
                    int threads,
                    int delayMs,
                    bool noVerifySsl,
                    int attempts,
                    const string& dictPath = "")
{
    SafePrint("\n🎲 [RandomizedFuzz] Starting enhanced endpoint discovery...");

    // Step 1: Establish baseline 404 fingerprint
    string sentinel = JoinUrl(baseUrl, "/__zombieapi_baseline_" + GenerateRandomString(8));
    HttpResult base = HttpRequest(sentinel, "GET", {}, "", delayMs, noVerifySsl);

    if (!base.success) {
        SafePrint("⚠️ [RandomizedFuzz] Could not establish baseline.");
        return;
    }

    string baselineFP = BodyFingerprint(base.body);
    long baselineStatus = base.status;

    SafePrint("📏 Baseline: HTTP " + to_string(baselineStatus) +
              " | " + to_string(base.size) + " bytes");

    ThreadPool pool(threads);
    mutex fuzzMutex;
    int hits = 0;
    unordered_set<string> attemptedUrls;  // Deduplication
    mutex attemptedMutex;
    vector<string> discoveredEndpoints;  // For recursive expansion
    mutex discoveredMutex;

    // Common suspicious prefixes
    vector<string> dynamic_prefixes = prefixes;
    vector<string> dynamic_words = words;

    // Enhanced wordlist with specialized terms
    vector<string> api_specific = {
        "resource", "collection", "item", "entities", "records",
        "query", "mutation", "subscription", "schema", "resolver",
        "login", "logout", "register", "token", "refresh", "oauth", "callback",
        "v1", "v2", "v3", "beta", "alpha", "stable", "latest", "legacy", "deprecated",
        "export", "import", "sync", "async", "batch", "bulk", "mass"
    };
    for (const auto& w : api_specific) dynamic_words.push_back(w);

    // Load dictionary file if provided
    if (!dictPath.empty()) {
        ifstream dictFile(dictPath);
        if (!dictFile.is_open()) {
            cerr << "❌ Could not open dictionary file: " << dictPath << "\n";
            return;
        }
        string line;
        int loaded = 0;
        while (getline(dictFile, line)) {
            // Trim whitespace
            size_t start = line.find_first_not_of(" \t\r\n");
            size_t end = line.find_last_not_of(" \t\r\n");
            if (start == string::npos) continue;
            string word = line.substr(start, end - start + 1);
            if (!word.empty() && word[0] != '#') {  // skip comments
                dynamic_words.push_back(word);
                loaded++;
            }
        }
        dictFile.close();
        SafePrint("📖 Loaded " + to_string(loaded) + " words from dictionary: " + dictPath);
    }

    {
        lock_guard<mutex> lock(g_learningMutex);

        for (const auto& p : g_learned_prefixes)
            dynamic_prefixes.push_back(p);

        for (const auto& t : g_learned_tokens)
            dynamic_words.push_back(t);
    }

    SafePrint("🎯 Word pool: " + to_string(dynamic_prefixes.size()) + " prefixes, " +
              to_string(dynamic_words.size()) + " words");

    // HTTP methods to probe
    const vector<string> methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"};

    // Header sets to try for content negotiation
    const vector<vector<string>> headerSets = {
        {"Accept: application/json"},
        {"Accept: application/xml"},
        {"Accept: text/xml"},
        {"X-Requested-With: XMLHttpRequest"},
        {"Accept: application/json", "X-Requested-With: XMLHttpRequest"}
    };

    for (int i = 0; i < attempts; i++) {
        pool.enqueue([&, i]() {

            static thread_local mt19937 rng(random_device{}());

            // === SMART PATH GENERATION ===
            string path;

            // 30% of the time, generate from discovered patterns
            if (i % 10 < 3) {
                lock_guard<mutex> lk(discoveredMutex);
                if (!discoveredEndpoints.empty()) {
                    string basePath = discoveredEndpoints[rng() % discoveredEndpoints.size()];
                    auto subPaths = GenerateSubPaths(basePath);
                    if (!subPaths.empty()) {
                        path = subPaths[rng() % subPaths.size()];
                    }
                }
            }

            // 70% of the time, generate random combinations
            if (path.empty()) {
                string prefix = dynamic_prefixes[rng() % dynamic_prefixes.size()];
                string word1  = dynamic_words[rng() % dynamic_words.size()];
                string word2  = dynamic_words[rng() % dynamic_words.size()];

                int mode = rng() % 6;  // Expanded from 5 to 6 modes

                switch (mode) {
                    case 0:
                        path = prefix + "/" + word1;
                        break;
                    case 1:
                        path = prefix + "/" + word1 + "/" + word2;
                        break;
                    case 2:
                        path = prefix + "/" + word1 + "_dump";
                        break;
                    case 3:
                        path = prefix + "/" + word1 + "_" + word1;
                        break;
                    case 4:
                        path = prefix + "/internal_" + word1;
                        break;
                    case 5:
                        // New pattern: path with numeric ID
                        path = prefix + "/" + word1 + "/" + to_string(rng() % 1000);
                        break;
                }
            }

            string candidate = JoinUrl(baseUrl, path);

            // === DEDUPLICATION ===
            {
                lock_guard<mutex> lk(attemptedMutex);
                if (attemptedUrls.count(candidate)) return;
                attemptedUrls.insert(candidate);
            }

            // === INITIAL PROBE WITH GET ===
            HttpResult r = HttpRequest(candidate, "GET", {}, "", delayMs, noVerifySsl);

            if (!r.success) return;

            // Skip obvious 404
            if (r.status == 404 || r.status == 410) return;

            // === FILTER 1: Must be valid endpoint status ===
            if (!IsValidEndpointStatus(r.status)) return;

            // === FILTER 2: Must look like an API response ===
            if (!IsApiResponse(r)) return;

            // === FILTER 2.5: Reject error-only responses (e.g., 405 with just {"detail":"Method Not Allowed"})
            // Skip for 429 (rate limit) — 429 itself indicates the endpoint exists
            if (r.status != 429 && IsErrorOnlyResponse(r.body)) {
                return;  // Response contains only error fields, not actual endpoint data
            }

            // === FILTER 3: Calculate confidence score ===
            int confidence = CalculateConfidenceScore(r);
            if (confidence < 50) return;  // Minimum confidence threshold

            // === FILTER 4: Multi-method verification ===
            // Try different HTTP methods to confirm it's a real endpoint
            vector<string> respondingMethods;
            for (const auto& method : methods) {
                if (method == "GET") {
                    respondingMethods.push_back(method);
                    continue;  // Already tested
                }
                HttpResult methodResult = HttpRequest(candidate, method, {}, "", delayMs, noVerifySsl);
                if (methodResult.success && IsValidEndpointStatus(methodResult.status)) {
                    respondingMethods.push_back(method);
                }
            }

            // Must respond to at least 2 methods (per FILTER 4 comment)
            if ((int)respondingMethods.size() < 2) return;

            // === FILTER 5: Content negotiation verification ===
            // Try with different Accept headers
            bool jsonResponse = false;
            bool xmlResponse = false;
            for (const auto& headers : headerSets) {
                HttpResult contentResult = HttpRequest(candidate, "GET", headers, "", delayMs, noVerifySsl);
                if (contentResult.success && IsApiResponse(contentResult)) {
                    if (contentResult.headers.find("application/json") != string::npos) {
                        jsonResponse = true;
                    }
                    if (contentResult.headers.find("application/xml") != string::npos ||
                        contentResult.headers.find("text/xml") != string::npos) {
                        xmlResponse = true;
                    }
                }
            }

            // === FILTER 6: VERIFY by re-fetching ===
            HttpResult verify = HttpRequest(candidate, "GET", {}, "", delayMs, noVerifySsl);
            if (!verify.success || !IsApiResponse(verify) || !IsValidEndpointStatus(verify.status)) {
                return;
            }

            // === FILTER 6.5: Verified response must also not be error-only ===
            if (verify.status != 429 && IsErrorOnlyResponse(verify.body)) {
                return;  // Verified response is also just an error message
            }

            // === FILTER 7: Final confidence check ===
            int finalConfidence = CalculateConfidenceScore(verify);
            if (finalConfidence < 60) return;  // Higher threshold after verification

            // ✅ VERIFIED API ENDPOINT - Classify it 
            string classify = "NORMAL";  // RandomizedFuzz finds real APIs, most are likely normal
            int score = finalConfidence;  // Use existing confidence as base
            
            // Higher confidence with success codes suggests real working API (not zombie)
            if (r.status == 200 && finalConfidence >= 80) {
                classify = "NORMAL";  
            } else if (finalConfidence < 50 || r.status == 401 || r.status == 403) {
                // Low confidence or auth-gated might be zombie/suspect
                score -= 20;
            }
            
            // Check path for versioning/deprecated indicators  
            if (candidate.find("/v0") != string::npos || 
                regex_search(candidate, regex(R"((/v[0-9]+)(/|$))"))) {
                classify = "ZOMBIE";  // Versioned endpoints are potential zombies
            }
            
            stringstream ss;
            ss << " 🎲 [" + classify + "] VERIFIED API: " << candidate << "\n"
               << "    Status: " << r.status
               << " | Size: " << r.size << " bytes"
               << " | Confidence: " << finalConfidence << "/100"  
               << " | Score: " << score;
            if (!respondingMethods.empty()) {
                ss << " | Methods: ";
                for (size_t j = 0; j < respondingMethods.size(); j++) {
                    if (j > 0) ss << ",";
                    ss << respondingMethods[j];
                }
            }

            SafePrint(ss.str());

            // Add endpoint with method information
            string endpointWithMethod = candidate;
            if (!respondingMethods.empty() && respondingMethods[0] != "GET") {
                endpointWithMethod += " [" + respondingMethods[0] + "]";
            }
            AddEndpoint(endpointWithMethod);

            // Add to discovered endpoints for recursive expansion
            {
                lock_guard<mutex> lk(discoveredMutex);
                discoveredEndpoints.push_back(candidate);
            }

            lock_guard<mutex> lk(fuzzMutex);
            hits++;
        });
    }

    pool.waitAll();

    SafePrint("✅ [RandomizedFuzz] Complete. Candidates found: "
        + to_string(hits) + " out of " + to_string(attempts));
}
// ------------------------------------------------------------
// -                 Main Program Function                    -
// ------------------------------------------------------------
int main(int argc, const char* argv[]) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        cerr << "❌ Failed to init libcurl" << endl;
        return 1;
    }

    CLIOptions opts = ParseArgs(argc, argv);
    if (opts.url.empty()) {
        cerr << "❌ Usage: ZombieAPI <url> [--help]\n";
        curl_global_cleanup();
        return 1;
    }
    if (opts.url.find("http://") != 0 && opts.url.find("https://") != 0) {
        cerr << "❌ URL must start with http:// or https://\n";
        curl_global_cleanup();
        return 1;
    }

    SafePrint("\n🧠 Application Version: " + to_string(APP_VERSION));
    SafePrint("🚀 Scanning: " + opts.url);
    SafePrint("🧵 Using " + to_string(opts.threads) + " threads");
    SafePrint("📊 Crawl depth: " + to_string(opts.crawlDepth));
    if (opts.noVerifySsl)
        SafePrint("⚠️  SSL verification disabled");

    HttpResult res = HttpRequest(opts.url, "GET", {}, "", opts.delayMs, opts.noVerifySsl);
    if (!res.success) {
        SafePrint("❌ Request failed (Status: " + to_string(res.status) + ")");
        curl_global_cleanup();
        return 1;
    }

    SafePrint("📦 Received " + to_string(res.size) + " bytes (HTTP " +
              to_string(res.status) + ")");

    if (IsApiResponse(res)) {
        SafePrint("🧟 ROOT URL IS AN API ENDPOINT!");
        AddEndpoint(opts.url);
    }

    auto startEndpoints = ExtractEndpoints(res.body, res.effectiveUrl);
    SafePrint("🎯 Initial endpoints found on start page: " +
              to_string(startEndpoints.size()));
    for (const auto& ep : startEndpoints) {
        AddEndpoint(ep);
    }

    // Also fetch the root URL (scheme+host) to extract additional endpoints
    {
        string rootUrl = ExtractHost(opts.url);
        if (!rootUrl.empty()) {
            HttpResult rootRes = HttpRequest(rootUrl + "/", "GET", {}, "", opts.delayMs, opts.noVerifySsl);
            if (rootRes.success) {
                SafePrint("📦 Root page: " + to_string(rootRes.size) + " bytes (HTTP " +
                          to_string(rootRes.status) + ")");
                auto rootEndpoints = ExtractEndpoints(rootRes.body, rootUrl);
                if (!rootEndpoints.empty()) {
                    SafePrint("🎯 Found " + to_string(rootEndpoints.size()) + " endpoints from root page");
                    for (const auto& ep : rootEndpoints) {
                        AddEndpoint(ep);
                    }
                }
            }
        }
    }

    // Always probe common API paths as a baseline discovery step
    FuzzCommonEndpoints(opts.url, opts.threads, opts.delayMs);

    auto pages = CrawlConcurrent(opts.url,
                                 opts.crawlDepth,
                                 opts.threads,
                                 opts.delayMs);

    vector<string> allEndpoints;
    {
        lock_guard<mutex> lk(g_endpointsMutex);
        allEndpoints.assign(g_endpoints.begin(), g_endpoints.end());
    }

    SafePrint("\n🔍 Endpoints found after crawl: " +
              to_string(allEndpoints.size()));
    for (const auto& ep : allEndpoints) {
        SafePrint("   🧟 " + ep);
    }

    // --- Zombie / Hidden API Discovery Modules ---
    if (opts.passiveRecon) {
        PassiveRecon(opts.url, opts.threads, opts.delayMs, opts.noVerifySsl);
    }
    if (opts.headerProbe && !allEndpoints.empty()) {
        HeaderProbe(allEndpoints, opts.threads, opts.delayMs, opts.noVerifySsl);
    }
    if (opts.changelogHunt) {
        ChangelogHunt(opts.url, opts.threads, opts.delayMs, opts.noVerifySsl);
    }
    if (opts.diffFuzz) {
        DiffFuzz(opts.url, {}, opts.threads, opts.delayMs, opts.noVerifySsl);
    }
    if (opts.randomFuzz) {
        RandomizedFuzz(opts.url, opts.threads, opts.delayMs, opts.noVerifySsl, RANDOM_FUZZ_LIMIT, opts.fuzzDict);
    }
    // Probe sub-paths on all discovered endpoints
    {
        lock_guard<mutex> lk(g_endpointsMutex);
        allEndpoints.assign(g_endpoints.begin(), g_endpoints.end());
    }
    if (!allEndpoints.empty()) {
        ProbeSubPaths(opts.url, allEndpoints, opts.threads, opts.delayMs, opts.noVerifySsl);
    }
    // Final snapshot after all discovery modules complete
    {
        lock_guard<mutex> lk(g_endpointsMutex);
        allEndpoints.assign(g_endpoints.begin(), g_endpoints.end());
    }
    if (opts.apiOnly) {
        SafePrint("\n--- Final Zombie API Report (API Only) ---");
        unordered_set<string> checked;
        int apiCount = 0;

        // First, check the pages we already crawled
        for (const auto& page : pages) {
            if (!page.effectiveUrl.empty()) {
                checked.insert(page.effectiveUrl);
            }
            if (IsApiResponse(page)) {
                SafePrint("   🧟 " + page.effectiveUrl);
                apiCount++;
            }
        }
        // Then, check endpoints found by modules that we haven't seen yet
        for (const auto& ep : allEndpoints) {
            if (ep.empty() || checked.find(ep) != checked.end()) {
                continue;
            }
            checked.insert(ep);
            // Construct full URL - ep may be relative (e.g., "/ws/2/artist") or absolute
            string fullUrl = (ep.find("http://") == 0 || ep.find("https://") == 0)
                           ? ep : JoinUrl(opts.url, ep);
            HttpResult r = HttpRequest(fullUrl, "GET", {}, "", opts.delayMs, opts.noVerifySsl);
            if (r.success && IsApiResponse(r)) {
                SafePrint("   🧟 " + fullUrl);
                apiCount++;
            }
        }

        SafePrint("🔍 Total distinct API endpoints: " + to_string(apiCount));
    } else {
        // Enhanced Final Report with Statistics and Classification Summary
        SafePrint("\n" + string(60, '='));
        SafePrint("         ZOMBIE API DISCOVERY - FINAL REPORT          ");
        SafePrint(string(60, '=') + "\n");
        
        int zombieCount = 0, normalCount = 0;
        vector<string> zombieEndpoints, normalEndpoints;
        unordered_map<string, string> endpointClassifications;
        
        // Classify all endpoints
        for (const auto& ep : allEndpoints) {
            if (ep.find("[source-map]") == 0 || ep.find("[shadow") != string::npos) continue;
            
            bool isVersioned = regex_search(ep, regex(R"((v[0-9]+|beta|alpha|legacy|deprecated)[/_\s])"));
            
            if (isVersioned) {
                endpointClassifications[ep] = "ZOMBIE";
                zombieCount++;
                zombieEndpoints.push_back(ep);
            } else {
                endpointClassifications[ep] = "NORMAL";
                normalCount++;
                normalEndpoints.push_back(ep);
            }
        }
        
        int total = zombieCount + normalCount;
        
        // Summary Statistics
        SafePrint("\n📊 SUMMARY STATISTICS");
        SafePrint(string(40, '-'));
        if (total > 0) {
            double zombiePct = (double)zombieCount / total * 100.0;
            double normalPct = (double)normalCount / total * 100.0;
            
            SafePrint("Total Endpoints Discovered:      " + to_string(total));
            SafePrint("Zombie APIs Detected:            " + to_string(zombieCount) + 
                     " (" + to_string((int)zombiePct) + "%)");
            SafePrint("Normal API Endpoints:            " + to_string(normalCount) + 
                     " (" + to_string((int)normalPct) + "%)\n");
        } else {
            SafePrint("No valid endpoints found in scan.\n");
        }
        
        // Key Discoveries - Zombies
        if (!zombieEndpoints.empty()) {
            SafePrint("\n🧟 ZOMBIE API ENDPOINTS DETECTED (Lifecycle Violations)");
            SafePrint(string(50, '-'));
            for (const auto& ep : zombieEndpoints) {
                SafePrint("  ⚡ " + ep);
            }
        }
        
        // Key Discoveries - Normal APIs (if any)
        if (!normalEndpoints.empty()) {
            SafePrint("\n✅ NORMAL API ENDPOINTS");
            SafePrint(string(50, '-'));
            int shown = 0;
            for (const auto& ep : normalEndpoints) {
                if (shown < 15 || zombieCount > 0) {
                    SafePrint("  ✓ " + ep);
                    shown++;
                } else if (shown == 15 && zombieCount == 0) {
                    SafePrint("  ... and " + to_string(normalEndpoints.size() - 15) + " more");  
                    break;
                }
            }
        }
        
        // Recommendations
        if (zombieCount > 0) {
            SafePrint("\n📋 SECURITY RECOMMENDATIONS");
            SafePrint(string(40, '-'));
            
            SafePrint("  • Review and document all zombie APIs or decommission");
            SafePrint("  • Implement API lifecycle governance policies");
            SafePrint("  • Add versioning enforcement at gateway level");
            SafePrint("  • Schedule deprecated endpoints for removal\n");
        } else {
            SafePrint("\n✅ SCAN COMPLETE: No zombie APIs detected!");
            SafePrint("   All endpoints appear to be properly documented and current.\n");
        }
        
        SafePrint(string(60, '='));
    }
    SafePrint("\n--- Crawl Results ---");
    for (const auto& page : pages) {
        string apiMarker = IsApiResponse(page) ? " 🧟 API" : "";
        SafePrint("🎯 " + page.effectiveUrl + " (" +
                  to_string(page.status) + ") " +
                  to_string(page.size) + " bytes" + apiMarker);
    }
    if (!opts.outfile.empty()) {
        SafePrint("\n--- Saving Results to CSV ---");
        ofstream f(opts.outfile);
        if (!f.is_open()) {
            cerr << "❌ Could not open outfile: " << opts.outfile << "\n";
        } else {
            // Build CSV records: use crawl results first (they have status/size),
            // then add any endpoints from g_endpoints that weren't crawled
            vector<CsvRecord> records;
            unordered_set<string> seen;

            // Add crawled pages
            for (const auto& page : pages) {
                if (page.effectiveUrl.empty()) continue;
                seen.insert(page.effectiveUrl);
                CsvRecord rec;
                rec.url = page.effectiveUrl;
                rec.status = page.status;
                rec.size = page.size;
                rec.isApi = IsApiResponse(page);
                rec.source = "crawl";
                records.push_back(rec);
            }

            // Add endpoints from discovery modules that weren't crawled
            for (const auto& ep : allEndpoints) {
                if (ep.empty() || seen.count(ep)) continue;
                seen.insert(ep);
                CsvRecord rec;
                rec.url = ep;
                rec.status = 0;
                rec.size = 0;
                rec.isApi = false;

                // Strip annotation prefixes to get the actual URL
                string actualUrl = ep;
                if (ep.find("[source-map]") == 0) {
                    rec.isApi = false;  // Source map entries are file paths, not URLs
                    rec.source = "passive-recon";
                    rec.url = ep;  // Keep the annotation
                    records.push_back(rec);
                    continue;
                } else if (ep.find("[shadow via:") != string::npos) {
                    rec.isApi = true;  // Shadow routes are endpoints that exist
                    rec.source = "header-probe";
                    rec.url = ep;  // Keep the annotation
                    records.push_back(rec);
                    continue;
                } else {
                    rec.source = "discovery";
                }

                // Actually check if this endpoint is an API by making a request
                HttpResult verifyResult = HttpRequest(actualUrl, "GET", {}, "",
                                                     opts.delayMs, opts.noVerifySsl);
                if (verifyResult.success) {
                    rec.status = verifyResult.status;
                    rec.size = verifyResult.size;
                    // Skip error-only responses (rate limit, 400, etc.)
                    if (verifyResult.status == 429 || IsErrorOnlyResponse(verifyResult.body)) {
                        rec.isApi = false;
                    } else {
                        rec.isApi = IsApiResponse(verifyResult);
                    }
                }

                records.push_back(rec);
            }

            // Write CSV header
            f << "url,status,size_bytes,is_api,source\n";

            // Write data rows
            for (const auto& rec : records) {
                f << CsvEscape(rec.url) << ","
                  << rec.status << ","
                  << rec.size << ","
                  << (rec.isApi ? "true" : "false") << ","
                  << CsvEscape(rec.source) << "\n";
            }
            f.close();
            SafePrint("✅ Saved " + to_string(records.size()) +
                      " record(s) to: " + opts.outfile);
        }
    }

    curl_global_cleanup();
    return 0;
}
