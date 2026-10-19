#ifndef NVME_BPF_HTTP_SERVER_H_
#define NVME_BPF_HTTP_SERVER_H_

#include <atomic>
#include <deque>
#include <functional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace nvme_bpf {

struct HttpRequest {
  std::string method;  // e.g. "GET".
  std::string path;    // URL-decoded path without the query, e.g. "/api".
  absl::flat_hash_map<std::string, std::string> query;  // URL-decoded.

  // Returns the query parameter `name` or `default_value` if absent.
  std::string QueryParam(absl::string_view name,
                         absl::string_view default_value = "") const;
};

struct HttpResponse {
  int status = 200;
  std::string content_type = "text/plain; charset=utf-8";
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;

  static HttpResponse Text(int status, std::string body);
};

// Parses an HTTP/1.x request line and headers (everything up to and
// including the empty line). Only the request line is interpreted.
absl::StatusOr<HttpRequest> ParseHttpRequest(absl::string_view head);

// Decodes %XX escapes, and '+' as space when `plus_is_space`.
std::string UrlDecode(absl::string_view in, bool plus_is_space);

// A minimal HTTP/1.1 server intended for serving a local dashboard.
//
// * Only GET and HEAD are supported.
// * Every response closes the connection (no keep-alive).
// * Connections are handled by a fixed pool of worker threads.
class HttpServer {
 public:
  using Handler = std::function<HttpResponse(const HttpRequest&)>;

  explicit HttpServer(int num_workers = 4) : num_workers_(num_workers) {}
  ~HttpServer();

  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  // Registers a handler for an exact path. Must be called before Start().
  void AddHandler(std::string path, Handler handler);

  // Binds to `address`:`port` and starts serving in background threads.
  // `address` may be an IPv4/IPv6 literal or a host name. Port 0 picks a free
  // port, see port().
  absl::Status Start(const std::string& address, int port);

  // Stops accepting connections and waits for in-flight requests to finish.
  void Stop();

  // The port the server listens on, valid after a successful Start().
  int port() const { return port_; }

 private:
  void AcceptLoop();
  void WorkerLoop();
  void ServeConnection(int fd) const;
  HttpResponse Dispatch(const HttpRequest& request) const;
  bool HasWorkOrStopping() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    return !pending_.empty() || stopping_.load();
  }

  const int num_workers_;
  absl::flat_hash_map<std::string, Handler> handlers_;
  int listen_fd_ = -1;
  int port_ = 0;
  std::atomic<bool> stopping_{false};
  std::thread accept_thread_;
  std::vector<std::thread> workers_;

  absl::Mutex mu_;
  std::deque<int> pending_ ABSL_GUARDED_BY(mu_);
};

}  // namespace nvme_bpf

#endif  // NVME_BPF_HTTP_SERVER_H_
