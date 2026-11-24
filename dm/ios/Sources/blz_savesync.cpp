// save_sync - see save_sync.h. Talks to Blazing tools/savesync/savesync.py `serve` (mac1, tailnet :4481):
//   POST /v1/<game>/upload?device=<id>  body = tar of the synced folders -> {"result","apply","current",...}
//   GET  /v1/<game>/current.tar         the store's current save (when apply is true)
//   POST /v1/<game>/ack?device=<id>&hash=<h>  after the new save is written and re-hashed
// The hash is the store's tree hash: sha256 over (path, NUL, length, NUL, bytes) of every file in path order,
// first 16 hex digits. Plain BSD sockets (no ATS, no URLSession), so the code is the same on iOS and Android.
#include "blz_savesync.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

namespace blz_savesync {
namespace fs = std::filesystem;

namespace {

// ------------------------------------------------------------------------------------------- SHA-256
struct Sha256 {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint8_t buf[64];
  size_t len = 0;
  uint64_t bits = 0;
  static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
  void block(const uint8_t* p) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = uint32_t(p[i * 4]) << 24 | uint32_t(p[i * 4 + 1]) << 16 | uint32_t(p[i * 4 + 2]) << 8 | p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
      uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  void update(const void* data, size_t n) {
    auto* p = static_cast<const uint8_t*>(data);
    bits += uint64_t(n) * 8;
    while (n) {
      size_t take = std::min(n, size_t(64) - len);
      memcpy(buf + len, p, take);
      len += take; p += take; n -= take;
      if (len == 64) { block(buf); len = 0; }
    }
  }
  std::string hex() {
    uint64_t total = bits;
    uint8_t pad = 0x80, zero = 0;
    update(&pad, 1);
    while (len != 56) update(&zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = uint8_t(total >> (56 - 8 * i));
    update(lenb, 8);
    char out[65];
    for (int i = 0; i < 8; i++) snprintf(out + i * 8, 9, "%08x", h[i]);
    return std::string(out, 64);
  }
};

// ------------------------------------------------------------------------------------------- trees
struct File {
  std::string data;
  int64_t mtime = 0;
};
using Tree = std::map<std::string, File>;  // std::map = byte order = the store's sorted() order (ASCII paths)

Config g_cfg;
std::mutex g_mu;
std::string g_synced;     // hash the store and this device agreed on
std::string g_last_sent;  // last hash we sent
std::atomic<bool> g_started{false};

bool IsTmp(const std::string& rel) {
  static const std::string kTmp = ".savesync-tmp";
  return rel.size() > kTmp.size() && rel.compare(rel.size() - kTmp.size(), kTmp.size(), kTmp) == 0;
}

bool InScope(const std::string& rel) {
  if (IsTmp(rel)) return false;
  for (const auto& p : g_cfg.include) {
    std::string bare = p;
    if (!bare.empty() && bare.back() == '/') bare.pop_back();
    if (rel == bare || rel.compare(0, p.size(), p) == 0) return true;
  }
  return false;
}

void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void Log(const char* fmt, ...) {
  char msg[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof msg, fmt, ap);
  va_end(ap);
  time_t t = time(nullptr);
  char ts[32];
  strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
  auto path = g_cfg.root.parent_path() / "savesync.log";
  std::error_code ec;
  if (fs::file_size(path, ec) > (1 << 20)) fs::rename(path, path.string() + ".old", ec);
  if (FILE* f = fopen(path.c_str(), "a")) {
    fprintf(f, "[%s] %s\n", ts, msg);
    fclose(f);
  }
}

// Calls fn(rel, path) for every regular file in scope. Walks only the include folders (the save root also holds
// the DLC content folder, logs and caches: ~800 files on the iPhone), with lexical relative paths: walking the whole
// root with fs::relative() (a realpath per file) every poll kept a third of a CPU core busy (17 Nov, measured).
template <typename Fn>
void ForEachInScope(Fn&& fn) {
  std::error_code ec;
  for (const auto& p : g_cfg.include) {
    fs::path start = g_cfg.root / p;
    if (fs::is_regular_file(start, ec)) {
      std::string rel = start.lexically_relative(g_cfg.root).generic_string();
      if (InScope(rel)) fn(rel, start);
      continue;
    }
    if (!fs::is_directory(start, ec)) continue;
    for (auto it = fs::recursive_directory_iterator(start, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec)) {
      if (!it->is_regular_file(ec)) continue;
      std::string rel = it->path().lexically_relative(g_cfg.root).generic_string();
      if (InScope(rel)) fn(rel, it->path());
    }
  }
}

Tree ReadTree() {
  Tree tree;
  ForEachInScope([&](const std::string& rel, const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    File f;
    f.data.assign(std::istreambuf_iterator<char>(in), {});
    struct stat st {};
    if (stat(path.c_str(), &st) == 0) f.mtime = st.st_mtime;
    tree[rel] = std::move(f);
  });
  return tree;
}

std::string Signature() {  // cheap change check: names, sizes, dates
  std::map<std::string, std::string> rows;
  ForEachInScope([&](const std::string& rel, const fs::path& path) {
    struct stat st {};
    if (stat(path.c_str(), &st) == 0) rows[rel] = std::to_string(st.st_size) + "/" + std::to_string(st.st_mtime);
  });
  std::string sig;
  for (auto& [k, v] : rows) sig += k + "=" + v + ";";
  return sig;
}

std::string TreeHash(const Tree& tree) {
  Sha256 s;
  for (const auto& [rel, f] : tree) {
    std::string len = std::to_string(f.data.size());
    s.update(rel.data(), rel.size());
    s.update("", 1);
    s.update(len.data(), len.size());
    s.update("", 1);
    s.update(f.data.data(), f.data.size());
  }
  return s.hex().substr(0, 16);
}

// ------------------------------------------------------------------------------------------- tar (ustar)
void Octal(char* field, size_t width, uint64_t v) {  // width-1 digits + NUL
  snprintf(field, width, "%0*llo", int(width - 1), (unsigned long long)v);
}

std::string TarWrite(const Tree& tree) {
  std::string out;
  for (const auto& [rel, f] : tree) {
    char h[512] = {};
    std::string name = rel, prefix;
    if (name.size() > 100) {  // ustar: split at a '/' into prefix (<=155) + name (<=100)
      size_t cut = std::string::npos;
      for (size_t i = rel.find('/'); i != std::string::npos && i <= 155; i = rel.find('/', i + 1))
        if (rel.size() - i - 1 <= 100) { cut = i; break; }
      if (cut == std::string::npos) continue;
      prefix = rel.substr(0, cut);
      name = rel.substr(cut + 1);
    }
    memcpy(h, name.data(), name.size());
    Octal(h + 100, 8, 0644);
    Octal(h + 108, 8, 0);
    Octal(h + 116, 8, 0);
    Octal(h + 124, 12, f.data.size());
    Octal(h + 136, 12, uint64_t(std::max<int64_t>(f.mtime, 0)));
    memset(h + 148, ' ', 8);
    h[156] = '0';
    memcpy(h + 257, "ustar", 6);
    memcpy(h + 263, "00", 2);
    memcpy(h + 345, prefix.data(), prefix.size());
    unsigned sum = 0;
    for (unsigned char c : h) sum += c;
    snprintf(h + 148, 8, "%06o", sum);
    h[155] = ' ';
    out.append(h, 512);
    out += f.data;
    out.append((512 - f.data.size() % 512) % 512, '\0');
  }
  out.append(1024, '\0');
  return out;
}

uint64_t ParseOctal(const char* p, size_t n) {
  uint64_t v = 0;
  for (size_t i = 0; i < n && p[i]; i++)
    if (p[i] >= '0' && p[i] <= '7') v = v * 8 + (p[i] - '0');
  return v;
}

bool TarRead(const std::string& blob, Tree& tree) {
  size_t pos = 0;
  std::string long_name;
  while (pos + 512 <= blob.size()) {
    const char* h = blob.data() + pos;
    if (std::all_of(h, h + 512, [](char c) { return c == 0; })) return true;
    uint64_t size = ParseOctal(h + 124, 12);
    char type = h[156];
    std::string name(h, strnlen(h, 100));
    if (memcmp(h + 257, "ustar", 5) == 0 && h[345]) name = std::string(h + 345, strnlen(h + 345, 155)) + "/" + name;
    pos += 512;
    if (pos + size > blob.size()) return false;
    std::string data = blob.substr(pos, size);
    pos += (size + 511) / 512 * 512;
    if (type == 'x') {  // pax: "<len> path=<name>\n"
      size_t at = data.find(" path=");
      if (at != std::string::npos) long_name = data.substr(at + 6, data.find('\n', at) - at - 6);
      continue;
    }
    if (type == 'L') { long_name = std::string(data.c_str()); continue; }
    if (type == 'g') continue;
    if (!long_name.empty()) { name = long_name; long_name.clear(); }
    if (type != '0' && type != '\0') continue;
    while (name.compare(0, 2, "./") == 0) name = name.substr(2);
    if (name.empty() || name[0] == '/' || name.find("..") != std::string::npos || !InScope(name)) continue;
    tree[name] = File{std::move(data), int64_t(ParseOctal(h + 136, 12))};
  }
  return true;
}

// ------------------------------------------------------------------------------------------- HTTP
struct Reply {
  int status = 0;  // 0 = no connection
  std::string body;
};

Reply Http(const char* method, const std::string& path, const std::string& body, int timeout_ms) {
  Reply r;
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(g_cfg.host.c_str(), std::to_string(g_cfg.port).c_str(), &hints, &res) != 0 || !res) return r;
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) { freeaddrinfo(res); return r; }
#ifdef SO_NOSIGPIPE
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  int rc = connect(fd, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  if (rc != 0 && errno == EINPROGRESS) {
    pollfd p{fd, POLLOUT, 0};
    int err = 0;
    socklen_t el = sizeof err;
    if (poll(&p, 1, timeout_ms) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) rc = 0;
  }
  if (rc != 0) { close(fd); return r; }
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
  timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  std::string req = std::string(method) + " " + path + " HTTP/1.1\r\nHost: " + g_cfg.host + "\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif
  for (size_t off = 0; off < req.size();) {
    ssize_t n = send(fd, req.data() + off, req.size() - off, flags);
    if (n <= 0) { close(fd); return r; }
    off += size_t(n);
  }
  std::string resp;
  char buf[16384];
  for (ssize_t n; (n = recv(fd, buf, sizeof buf, 0)) > 0;) resp.append(buf, size_t(n));
  close(fd);
  size_t split = resp.find("\r\n\r\n");
  if (resp.compare(0, 5, "HTTP/") != 0 || split == std::string::npos) return r;
  r.status = atoi(resp.c_str() + resp.find(' ') + 1);
  r.body = resp.substr(split + 4);
  return r;
}

std::string JsonStr(const std::string& j, const char* key) {  // flat JSON from savesync.py: "key": "value"
  std::string k = std::string("\"") + key + "\": ";
  size_t at = j.find(k);
  if (at == std::string::npos) return "";
  at += k.size();
  if (j[at] != '"') return j.substr(at, j.find_first_of(",}", at) - at);  // true/false/null/number
  return j.substr(at + 1, j.find('"', at + 1) - at - 1);
}

// ------------------------------------------------------------------------------------------- sync steps
void Backup(const Tree& tree, const std::string& hash) {
  auto dir = g_cfg.root.parent_path() / "savesync-backup";
  char ts[32];
  time_t t = time(nullptr);
  strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", localtime(&t));
  auto dst = dir / (std::string(ts) + "_" + hash);
  std::error_code ec;
  for (const auto& [rel, f] : tree) {
    fs::create_directories((dst / rel).parent_path(), ec);
    std::ofstream(dst / rel, std::ios::binary).write(f.data.data(), std::streamsize(f.data.size()));
  }
  std::vector<fs::path> all;  // keep the newest 10
  for (auto& e : fs::directory_iterator(dir, ec)) all.push_back(e.path());
  std::sort(all.begin(), all.end());
  for (size_t i = 0; i + 10 < all.size(); i++) fs::remove_all(all[i], ec);
}

bool Write(const Tree& want, const Tree& have) {
  std::error_code ec;
  for (const auto& [rel, f] : want) {
    auto dst = g_cfg.root / rel;
    fs::create_directories(dst.parent_path(), ec);
    auto tmp = dst.string() + ".savesync-tmp";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      if (!out.write(f.data.data(), std::streamsize(f.data.size())) || !out.flush()) return false;
    }
    if (rename(tmp.c_str(), dst.c_str()) != 0) return false;
    timeval tv[2] = {{time_t(f.mtime), 0}, {time_t(f.mtime), 0}};
    utimes(dst.c_str(), tv);
  }
  for (const auto& [rel, f] : have)
    if (!want.count(rel)) fs::remove(g_cfg.root / rel, ec);
  return true;
}

std::string Q() { return "?device=" + g_cfg.device; }

// Launch: the game has not read its save yet, so a newer store save may replace it here (after a backup).
bool LaunchSync() {
  Tree have = ReadTree();
  std::string h = have.empty() ? "" : TreeHash(have);
  auto t0 = std::chrono::steady_clock::now();
  Reply r = Http("POST", "/v1/" + g_cfg.game + "/upload" + Q(), TarWrite(have), 4000);
  if (r.status != 200) {
    Log("launch: store not reachable (%s:%d, http %d) - playing the local save %s", g_cfg.host.c_str(), g_cfg.port,
        r.status, h.c_str());
    return false;
  }
  std::string result = JsonStr(r.body, "result"), cur = JsonStr(r.body, "current");
  Log("launch: local %s -> store says %s (current %s '%s')", h.c_str(), result.c_str(), cur.c_str(),
      JsonStr(r.body, "current_title").c_str());
  g_last_sent = h;
  if (JsonStr(r.body, "apply") != "true") {
    if (result != "stale" && result != "conflict-lost") g_synced = h;
    return true;
  }
  Reply t = Http("GET", "/v1/" + g_cfg.game + "/current.tar", "", 8000);
  Tree want;
  if (t.status != 200 || !TarRead(t.body, want) || TreeHash(want) != cur) {
    Log("launch: download of %s failed (http %d) - local save kept", cur.c_str(), t.status);
    return true;
  }
  if (!have.empty()) Backup(have, h);
  if (!Write(want, have)) {
    Log("launch: WRITE FAILED - local backup is in savesync-backup/");
    return true;
  }
  std::string back = TreeHash(ReadTree());
  if (back != cur) {
    Log("launch: read-back %s != %s - left as is, backup in savesync-backup/", back.c_str(), cur.c_str());
    return true;
  }
  Reply a = Http("POST", "/v1/" + g_cfg.game + "/ack" + Q() + "&hash=" + cur, "", 4000);
  g_synced = g_last_sent = cur;
  long ms = long(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count());
  Log("launch: now playing the store's save %s (old local %s kept in savesync-backup/, ack %d, %ld ms)", cur.c_str(),
      h.c_str(), a.status, ms);
  return true;
}

// In-game / background: only SEND. A newer store save is never written while the game runs.
bool SendIfChanged(const char* why, int timeout_ms) {
  Tree have = ReadTree();
  if (have.empty()) return true;
  std::string h = TreeHash(have);
  if (h == g_synced || h == g_last_sent) return true;
  Reply r = Http("POST", "/v1/" + g_cfg.game + "/upload" + Q(), TarWrite(have), timeout_ms);
  if (r.status != 200) {
    Log("%s: new local save %s, store not reachable (http %d) - will retry", why, h.c_str(), r.status);
    return false;
  }
  std::string result = JsonStr(r.body, "result");
  g_last_sent = h;
  if (result == "stale" || result == "conflict-lost")
    Log("%s: sent %s -> %s: the store has a newer save (%s) - it comes in at the next start", why, h.c_str(),
        result.c_str(), JsonStr(r.body, "current").c_str());
  else {
    g_synced = h;
    Log("%s: sent %s -> %s ('%s')", why, h.c_str(), result.c_str(), JsonStr(r.body, "current_title").c_str());
  }
  return true;
}

bool g_launch_ok = false;

void Loop(std::string handled) {  // handled = the save state right after the launch sync ("" = send when online)
  std::string last_sig = handled;
  int backoff = 0;
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(g_cfg.poll_seconds));
    std::string sig = Signature();
    if (sig != last_sig) { last_sig = sig; continue; }  // still being written: wait one more round
    if (sig == handled || backoff-- > 0) continue;
    std::lock_guard<std::mutex> lock(g_mu);
    if (SendIfChanged("save", 6000)) { handled = sig; backoff = 0; }
    else backoff = 6;  // ~30 s between retries while offline
  }
}

bool Disabled() {
  const char* home = getenv("HOME");
  if (!home) return false;
  std::ifstream f(fs::path(home) / "Documents" / "savesync.txt");
  std::string word;
  return f >> word && (word == "off" || word == "0");
}

}  // namespace

std::string Sha256Hex(const std::string& data) {
  Sha256 s;
  s.update(data.data(), data.size());
  return s.hex();
}

void Start(Config config) {
  if (g_started.exchange(true)) return;
  g_cfg = std::move(config);
  std::error_code ec;
  fs::create_directories(g_cfg.root, ec);
  if (Disabled()) {
    Log("off (Documents/savesync.txt)");
    return;
  }
  {
    std::lock_guard<std::mutex> lock(g_mu);
    g_launch_ok = LaunchSync();  // (Signature() for the loop is taken below, before the game can write)
    Log("started: %s:%d game %s device %s root %s", g_cfg.host.c_str(), g_cfg.port, g_cfg.game.c_str(),
        g_cfg.device.c_str(), g_cfg.root.c_str());
  }
  std::thread(Loop, g_launch_ok ? Signature() : std::string()).detach();
}

void OnBackground() {
  if (!g_started || Disabled()) return;
  std::unique_lock<std::mutex> lock(g_mu, std::try_to_lock);
  if (!lock.owns_lock()) return;  // a send is already running
  std::string sig = Signature();  // never send a save the game is still writing
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  if (Signature() != sig) {
    Log("background: save still being written - the next start sends it");
    return;
  }
  SendIfChanged("background", 3000);
}

}  // namespace blz_savesync

// blz (claude-iphone-switch-4, 24 Nov 2026): C entry points for the nxnative iOS app (main.m). The game and its synced files come from
// the build's env file: BLZ_SAVESYNC_GAME=<savesync store game> (unset = off), BLZ_SAVESYNC_INCLUDE=<comma list, folders end in />,
// optional BLZ_SAVESYNC_DEVICE (iphone-15pm), BLZ_SAVESYNC_HOST (mac1 tailnet), BLZ_SAVESYNC_PORT. Root = DM_SAVE (Documents/save).
// seed_dir: a copy of the store's save baked into the app (dm/save-seed): used ONLY when, after the launch sync, there is still no
// save in scope (a fresh install that could not reach the store), so a first start without network still begins from his save.
static void blz_seed_if_empty(const char* seed_dir) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!seed_dir || !fs::is_directory(seed_dir, ec)) return;
  if (!blz_savesync::ReadTree().empty()) return;
  int n = 0;
  for (auto it = fs::recursive_directory_iterator(seed_dir, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (!it->is_regular_file(ec)) continue;
    fs::path rel = it->path().lexically_relative(seed_dir), dst = blz_savesync::g_cfg.root / rel;
    fs::create_directories(dst.parent_path(), ec);
    if (fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec)) n++;
  }
  blz_savesync::Log("launch: no save and no store - started from the save baked into the app (%d files, dm/save-seed)", n);
  fprintf(stderr, "boot: save sync: no save and no store reachable - %d files from the save baked into the app\n", n);
}
extern "C" void blz_savesync_start(const char* save_root, const char* seed_dir) {
  const char* game = getenv("BLZ_SAVESYNC_GAME");
  if (!game || !*game || !save_root) return;
  blz_savesync::Config c;
  c.game = game;
  c.root = save_root;
  if (const char* d = getenv("BLZ_SAVESYNC_DEVICE")) c.device = d;
  if (const char* h = getenv("BLZ_SAVESYNC_HOST")) c.host = h;
  if (const char* p = getenv("BLZ_SAVESYNC_PORT")) c.port = atoi(p);
  c.include.clear();
  std::string inc = getenv("BLZ_SAVESYNC_INCLUDE") ? getenv("BLZ_SAVESYNC_INCLUDE") : "";
  std::stringstream ss(inc);
  for (std::string item; std::getline(ss, item, ',');) if (!item.empty()) c.include.push_back(item);
  if (c.include.empty()) return;
  fprintf(stderr, "boot: save sync with the savesync store: game %s, device %s, %zu entries (log Documents/savesync.log)\n", game, c.device.c_str(), c.include.size());
  blz_savesync::Start(std::move(c));
  blz_seed_if_empty(seed_dir);
}
extern "C" void blz_savesync_background(void) { blz_savesync::OnBackground(); }
