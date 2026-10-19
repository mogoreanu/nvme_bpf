#include "nvme_latency/http_server.h"

#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace nvme_bpf {
namespace {

constexpr size_t kMaxRequestHeadBytes = 32 * 1024;
constexpr size_t kMaxPendingConnections = 64;
constexpr int kSocketTimeoutSeconds = 10;
constexpr int kAcceptPollMs = 200;

absl::string_view StatusText(int status) {
  switch (status) {
    case 200:
      return "OK";
    case 204:
      return "No Content";
    case 400:
      return "Bad Request";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 431:
      return "Request Header Fields Too Large";
    case 500:
      return "Internal Server Error";
    case 503:
      return "Service Unavailable";
    default:
      return "Unknown";
  }
}

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool SendAll(int fd, absl::string_view data) {
  while (!data.empty()) {
    const ssize_t n = send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    data.remove_prefix(static_cast<size_t>(n));
  }
  return true;
}

std::string Serialize(const HttpResponse& response, bool include_body) {
  std::string out = absl::StrCat(
      "HTTP/1.1 ", response.status, " ", StatusText(response.status), "\r\n",
      "Content-Type: ", response.content_type, "\r\n",
      "Content-Length: ", response.body.size(), "\r\n",
      "Connection: close\r\n",
      "X-Content-Type-Options: nosniff\r\n",
      "Referrer-Policy: no-referrer\r\n");
  for (const auto& [name, value] : response.headers) {
    absl::StrAppend(&out, name, ": ", value, "\r\n");
  }
  out += "\r\n";
  if (include_body) out += response.body;
  return out;
}

void SetSocketTimeouts(int fd) {
  timeval tv{};
  tv.tv_sec = kSocketTimeoutSeconds;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

}  // namespace

std::string HttpRequest::QueryParam(absl::string_view name,
                                    absl::string_view default_value) const {
  auto it = query.find(name);
  return it == query.end() ? std::string(default_value) : it->second;
}

HttpResponse HttpResponse::Text(int status, std::string body) {
  HttpResponse response;
  response.status = status;
  response.body = std::move(body);
  return response;
}

std::string UrlDecode(absl::string_view in, bool plus_is_space) {
  std::string out;
  out.reserve(in.size());
  for (size_t i = 0; i < in.size(); ++i) {
    const char c = in[i];
    if (c == '%' && i + 2 < in.size()) {
      const int hi = HexValue(in[i + 1]);
      const int lo = HexValue(in[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>(hi * 16 + lo));
        i += 2;
        continue;
      }
    }
    out.push_back(plus_is_space && c == '+' ? ' ' : c);
  }
  return out;
}

absl::StatusOr<HttpRequest> ParseHttpRequest(absl::string_view head) {
  const size_t eol = head.find("\r\n");
  if (eol == absl::string_view::npos) {
    return absl::InvalidArgumentError("Missing request line terminator");
  }
  const std::vector<absl::string_view> parts =
      absl::StrSplit(head.substr(0, eol), ' ', absl::SkipEmpty());
  if (parts.size() != 3 || !absl::StartsWith(parts[2], "HTTP/1.")) {
    return absl::InvalidArgumentError("Malformed request line");
  }
  HttpRequest request;
  request.method = std::string(parts[0]);

  absl::string_view target = parts[1];
  if (target.empty() || target[0] != '/') {
    return absl::InvalidArgumentError("Only origin-form targets are supported");
  }
  if (const size_t hash = target.find('#'); hash != absl::string_view::npos) {
    target = target.substr(0, hash);
  }
  absl::string_view query;
  if (const size_t q = target.find('?'); q != absl::string_view::npos) {
    query = target.substr(q + 1);
    target = target.substr(0, q);
  }
  request.path = UrlDecode(target, /*plus_is_space=*/false);
  for (absl::string_view kv : absl::StrSplit(query, '&', absl::SkipEmpty())) {
    std::pair<absl::string_view, absl::string_view> key_value =
        absl::StrSplit(kv, absl::MaxSplits('=', 1));
    request.query[UrlDecode(key_value.first, /*plus_is_space=*/true)] =
        UrlDecode(key_value.second, /*plus_is_space=*/true);
  }
  return request;
}

HttpServer::~HttpServer() { Stop(); }

void HttpServer::AddHandler(std::string path, Handler handler) {
  handlers_[std::move(path)] = std::move(handler);
}

absl::Status HttpServer::Start(const std::string& address, int port) {
  if (listen_fd_ >= 0) return absl::FailedPreconditionError("Already started");

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  addrinfo* addrs = nullptr;
  const std::string port_str = absl::StrCat(port);
  const int rc = getaddrinfo(address.empty() ? nullptr : address.c_str(),
                             port_str.c_str(), &hints, &addrs);
  if (rc != 0) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Cannot resolve address '", address, "': ", gai_strerror(rc)));
  }
  absl::Cleanup free_addrs = [addrs] { freeaddrinfo(addrs); };

  absl::Status last_error = absl::UnavailableError("No usable address");
  for (addrinfo* ai = addrs; ai != nullptr; ai = ai->ai_next) {
    const int fd =
        socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) {
      last_error = absl::ErrnoToStatus(errno, "socket()");
      continue;
    }
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0 || listen(fd, 64) != 0) {
      last_error = absl::ErrnoToStatus(
          errno, absl::StrCat("Cannot listen on ", address, ":", port));
      close(fd);
      continue;
    }
    listen_fd_ = fd;
    break;
  }
  if (listen_fd_ < 0) return last_error;

  sockaddr_storage bound{};
  socklen_t bound_len = sizeof(bound);
  if (getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound),
                  &bound_len) == 0) {
    if (bound.ss_family == AF_INET6) {
      port_ = ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
    } else {
      port_ = ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
    }
  }

  stopping_ = false;
  for (int i = 0; i < num_workers_; ++i) {
    workers_.emplace_back([this] { WorkerLoop(); });
  }
  accept_thread_ = std::thread([this] { AcceptLoop(); });
  return absl::OkStatus();
}

void HttpServer::Stop() {
  {
    absl::MutexLock lock(mu_);
    if (stopping_.load() && listen_fd_ < 0) return;
    stopping_ = true;
  }
  if (accept_thread_.joinable()) accept_thread_.join();
  for (std::thread& worker : workers_) worker.join();
  workers_.clear();
  if (listen_fd_ >= 0) {
    close(listen_fd_);
    listen_fd_ = -1;
  }
}

void HttpServer::AcceptLoop() {
  while (!stopping_.load()) {
    pollfd pfd{};
    pfd.fd = listen_fd_;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, kAcceptPollMs) <= 0) continue;
    const int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) continue;
    SetSocketTimeouts(fd);
    bool queued = false;
    {
      absl::MutexLock lock(mu_);
      if (pending_.size() < kMaxPendingConnections) {
        pending_.push_back(fd);
        queued = true;
      }
    }
    if (!queued) {
      SendAll(fd, Serialize(HttpResponse::Text(503, "Server busy\n"), true));
      close(fd);
    }
  }
}

void HttpServer::WorkerLoop() {
  while (true) {
    int fd = -1;
    {
      absl::MutexLock lock(mu_);
      mu_.Await(absl::Condition(this, &HttpServer::HasWorkOrStopping));
      if (pending_.empty()) return;  // Stopping and no more work.
      fd = pending_.front();
      pending_.pop_front();
    }
    ServeConnection(fd);
    close(fd);
  }
}

void HttpServer::ServeConnection(int fd) const {
  std::string buffer;
  size_t head_end = std::string::npos;
  char chunk[4096];
  while (head_end == std::string::npos) {
    if (buffer.size() > kMaxRequestHeadBytes) {
      SendAll(fd, Serialize(HttpResponse::Text(431, "Request too large\n"),
                            true));
      return;
    }
    const ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return;  // Closed, timed out or failed.
    buffer.append(chunk, static_cast<size_t>(n));
    head_end = buffer.find("\r\n\r\n");
  }

  absl::StatusOr<HttpRequest> request =
      ParseHttpRequest(absl::string_view(buffer).substr(0, head_end + 4));
  HttpResponse response;
  bool include_body = true;
  if (!request.ok()) {
    response = HttpResponse::Text(400, absl::StrCat(request.status().message(),
                                                    "\n"));
  } else if (request->method == "GET" || request->method == "HEAD") {
    include_body = request->method == "GET";
    response = Dispatch(*request);
    VLOG(1) << request->method << " " << request->path << " -> "
            << response.status << " (" << response.body.size() << " bytes)";
  } else {
    response = HttpResponse::Text(405, "Method not allowed\n");
    response.headers.push_back({"Allow", "GET, HEAD"});
  }
  SendAll(fd, Serialize(response, include_body));
  shutdown(fd, SHUT_WR);
}

HttpResponse HttpServer::Dispatch(const HttpRequest& request) const {
  auto it = handlers_.find(request.path);
  if (it == handlers_.end()) {
    return HttpResponse::Text(404, absl::StrCat("Not found: ", request.path,
                                                "\n"));
  }
  return it->second(request);
}

}  // namespace nvme_bpf
