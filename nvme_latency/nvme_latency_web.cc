// nvme_latency_web: serves the NVMe latency histograms collected by
// `nvme_latency` as a live web dashboard.
//
// The two halves run with different privileges:
//   sudo nvme_latency --print=summary     # Loads the BPF program (root), and
//                                         # exports /run/nvme_latency/snapshot.
//   nvme_latency_web --port=8080          # Regular user: reads the snapshots
//                                         # and serves the dashboard.
// Then open http://localhost:8080/ (from another machine use an ssh tunnel:
//   ssh -L 8080:localhost:8080 <host>).
//
// To try the UI without the collector, serve simulated data:
//   bazel run -c opt //nvme_latency:nvme_latency_web -- --fake
//
// HTTP endpoints:
//   /                 The dashboard.
//   /api/config       Collection settings, including histogram buckets.
//   /api/series       Time series and histograms. Query parameters:
//                       window_s    Time window in seconds (default 300).
//                       max_points  Max points per series (default 600).
//   /healthz          Liveness check.

#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/flags.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "nvme_latency/fake_latency_source.h"
#include "nvme_latency/http_server.h"
#include "nvme_latency/latency_json.h"
#include "nvme_latency/latency_source.h"
#include "nvme_latency/latency_store.h"
#include "nvme_latency/snapshot_file.h"
#include "nvme_latency/web_assets.h"

ABSL_FLAG(std::string, http_address, "127.0.0.1",
          "Address to serve the dashboard on. Use 0.0.0.0 or :: to allow "
          "remote connections.");
ABSL_FLAG(int, port, 8080, "HTTP port. 0 picks a free port.");
ABSL_FLAG(std::string, snapshot_path, nvme_bpf::kDefaultSnapshotPath,
          "The snapshot file exported by `nvme_latency --snapshot_path`.");
ABSL_FLAG(bool, fake, false,
          "Serve simulated latency data instead of reading the snapshots of "
          "nvme_latency.");
ABSL_FLAG(uint64_t, fake_seed, 1, "Random seed for --fake.");
ABSL_FLAG(bool, fake_split_size, false,
          "Simulate the --split_size size classes with --fake.");
ABSL_FLAG(int, poll_interval_ms, 1000,
          "How often to read the snapshots (or simulate with --fake).");
ABSL_FLAG(int, history_s, 3600, "How much history to keep, in seconds.");
ABSL_FLAG(std::string, web_root, "",
          "If set, serve the UI files from this directory (e.g. "
          "nvme_latency/web in the source tree) instead of the embedded copies. "
          "Useful for UI development.");
ABSL_FLAG(bool, allow_root, false,
          "Allow running as root. The dashboard does not need any privilege, "
          "only the `nvme_latency` collector does.");

namespace nvme_bpf {
namespace {

volatile std::sig_atomic_t g_exiting = 0;
void HandleSignal(int) { g_exiting = 1; }

std::string Hostname() {
  char buffer[256] = {};
  if (gethostname(buffer, sizeof(buffer) - 1) != 0) return "unknown";
  return buffer;
}

int ParseIntParam(const HttpRequest& request, absl::string_view name,
                  int default_value, int min_value, int max_value) {
  int value = default_value;
  const std::string raw = request.QueryParam(name);
  if (!raw.empty() && !absl::SimpleAtoi(raw, &value)) value = default_value;
  return std::clamp(value, min_value, max_value);
}

HttpResponse JsonResponse(std::string body) {
  HttpResponse response;
  response.content_type = "application/json";
  response.body = std::move(body);
  response.headers.push_back({"Cache-Control", "no-store"});
  return response;
}

// The latest data and settings of the source, shared between the polling
// loop and the HTTP handlers. The store is replaced when the collector
// restarts or changes its settings (e.g. --lat_min_us).
class Dashboard {
 public:
  Dashboard(std::string source_name, absl::Duration history,
            absl::Duration poll_interval, bool baseline_first_snapshot)
      : history_(history), baseline_first_snapshot_(baseline_first_snapshot) {
    config_.source_name = "none";
    config_.hostname = Hostname();
    config_.history_s = absl::ToInt64Seconds(history);
    config_.sample_interval_ms = absl::ToInt64Milliseconds(poll_interval);
    config_.start_ms = absl::ToUnixMillis(absl::Now());
    store_ = std::make_shared<LatencyStore>(config_.params, history,
                                            absl::Now());
    status_.name = std::move(source_name);
    status_.healthy = false;
    status_.last_error = "Waiting for the first snapshot";
  }

  void OnSnapshot(const Snapshot& snapshot) {
    absl::MutexLock lock(mu_);
    if (!have_info_ || snapshot.info != info_) {
      if (have_info_) {
        LOG(INFO) << "The collector restarted or changed its settings, "
                     "resetting the history.";
      }
      have_info_ = true;
      info_ = snapshot.info;
      store_ = std::make_shared<LatencyStore>(info_.params, history_,
                                              info_.start_time,
                                              baseline_first_snapshot_);
      config_.source_name = info_.source;
      config_.params = info_.params;
      config_.start_ms = absl::ToUnixMillis(info_.start_time);
      config_.sample_interval_ms = absl::ToInt64Milliseconds(info_.interval);
      config_.split_size = info_.split_size;
      config_.ctrl_id_filter = info_.ctrl_id_filter;
      config_.nsid_filter = info_.nsid_filter;
    }
    store_->Add(snapshot);
    status_.healthy = true;
    status_.last_error.clear();
  }

  void OnError(const absl::Status& error) {
    absl::MutexLock lock(mu_);
    status_.healthy = false;
    status_.last_error = std::string(error.message());
    ++status_.read_errors;
  }

  std::string ConfigJson() const {
    absl::MutexLock lock(mu_);
    return ConfigToJson(config_, store_->bounds());
  }

  std::string SeriesJson(QueryOptions options) const {
    std::shared_ptr<LatencyStore> store;
    DashboardConfig config;
    SourceStatus status;
    {
      absl::MutexLock lock(mu_);
      store = store_;
      config = config_;
      status = status_;
    }
    options.min_step = absl::Milliseconds(config.sample_interval_ms);
    options.recent = std::max(absl::Seconds(5), 2 * options.min_step);
    return ReportToJson(store->Query(options, absl::Now()), status, config);
  }

 private:
  const absl::Duration history_;
  const bool baseline_first_snapshot_;
  mutable absl::Mutex mu_;
  bool have_info_ ABSL_GUARDED_BY(mu_) = false;
  SourceInfo info_ ABSL_GUARDED_BY(mu_);
  DashboardConfig config_ ABSL_GUARDED_BY(mu_);
  std::shared_ptr<LatencyStore> store_ ABSL_GUARDED_BY(mu_);
  SourceStatus status_ ABSL_GUARDED_BY(mu_);
};

void AddAssetHandlers(HttpServer& server) {
  const std::string web_root = absl::GetFlag(FLAGS_web_root);
  for (const WebAsset& asset : EmbeddedWebAssets()) {
    HttpServer::Handler handler = [asset, web_root](const HttpRequest&) {
      HttpResponse response;
      response.content_type = std::string(asset.content_type);
      response.headers.push_back({"Cache-Control", "no-cache"});
      if (web_root.empty()) {
        response.body = std::string(asset.content);
        return response;
      }
      // Development mode: only the embedded file names are served, so there
      // is no path traversal.
      std::ifstream file(absl::StrCat(web_root, asset.path), std::ios::binary);
      if (!file) {
        return HttpResponse::Text(
            500, absl::StrCat("Cannot read ", web_root, asset.path, "\n"));
      }
      std::stringstream contents;
      contents << file.rdbuf();
      response.body = contents.str();
      return response;
    };
    if (asset.path == "/index.html") server.AddHandler("/", handler);
    server.AddHandler(std::string(asset.path), std::move(handler));
  }
}

absl::Status Run() {
  if (geteuid() == 0 && !absl::GetFlag(FLAGS_allow_root)) {
    return absl::FailedPreconditionError(
        "nvme_latency_web does not need root, please run it as a regular "
        "user. Only the collector needs root: sudo nvme_latency. "
        "(--allow_root overrides this check.)");
  }
  const absl::Duration poll_interval = absl::Milliseconds(
      std::clamp(absl::GetFlag(FLAGS_poll_interval_ms), 100, 60000));
  const absl::Duration history =
      absl::Seconds(std::clamp(absl::GetFlag(FLAGS_history_s), 60, 7 * 86400));

  const bool fake = absl::GetFlag(FLAGS_fake);
  std::unique_ptr<LatencySource> source;
  if (fake) {
    FakeSourceOptions options;
    options.seed = absl::GetFlag(FLAGS_fake_seed);
    options.split_size = absl::GetFlag(FLAGS_fake_split_size);
    options.interval = poll_interval;
    source = CreateFakeLatencySource(options);
  } else {
    SnapshotFileSourceOptions options;
    options.path = absl::GetFlag(FLAGS_snapshot_path);
    source = CreateSnapshotFileSource(options);
  }
  // The collector may have been counting for a while: its first snapshot is
  // only a baseline.
  Dashboard dashboard(source->name(), history, poll_interval,
                      /*baseline_first_snapshot=*/!fake);

  HttpServer server;
  AddAssetHandlers(server);
  server.AddHandler("/healthz", [](const HttpRequest&) {
    return HttpResponse::Text(200, "ok\n");
  });
  server.AddHandler("/api/config", [&dashboard](const HttpRequest&) {
    return JsonResponse(dashboard.ConfigJson());
  });
  server.AddHandler("/api/series", [&](const HttpRequest& request) {
    QueryOptions options;
    options.window = absl::Seconds(ParseIntParam(
        request, "window_s", 300, 10, absl::ToInt64Seconds(history)));
    options.max_points = ParseIntParam(request, "max_points", 600, 10, 4000);
    return JsonResponse(dashboard.SeriesJson(options));
  });

  const std::string address = absl::GetFlag(FLAGS_http_address);
  if (absl::Status status = server.Start(address, absl::GetFlag(FLAGS_port));
      !status.ok()) {
    return status;
  }
  const bool ipv6 = address.find(':') != std::string::npos;
  std::cout << "nvme_latency_web: reading "
            << (fake ? std::string("simulated data")
                     : absl::GetFlag(FLAGS_snapshot_path))
            << ", serving on http://" << (ipv6 ? "[" : "") << address
            << (ipv6 ? "]" : "") << ":" << server.port() << "/" << std::endl;

  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);

  // Poll a quarter interval after the collector's (aligned) writes.
  const int64_t interval_ms = absl::ToInt64Milliseconds(poll_interval);
  const int64_t offset_ms = fake ? 0 : interval_ms / 4;
  auto next_tick = [interval_ms, offset_ms](absl::Time now) {
    return absl::FromUnixMillis(
        ((absl::ToUnixMillis(now) - offset_ms) / interval_ms + 1) *
            interval_ms +
        offset_ms);
  };
  absl::Time next = absl::Now();
  while (!g_exiting) {
    const absl::Time now = absl::Now();
    if (now < next) {
      absl::SleepFor(std::min(next - now, absl::Milliseconds(100)));
      continue;
    }
    next = next_tick(now);
    absl::StatusOr<Snapshot> snapshot = source->Read();
    if (snapshot.ok()) {
      dashboard.OnSnapshot(*snapshot);
    } else {
      dashboard.OnError(snapshot.status());
      LOG_EVERY_N_SEC(WARNING, 30) << snapshot.status();
    }
  }

  std::cout << "Exiting." << std::endl;
  server.Stop();
  return absl::OkStatus();
}

}  // namespace
}  // namespace nvme_bpf

int main(int argc, char** argv) {
  absl::SetProgramUsageMessage(
      "Serves a live web dashboard of NVMe request latency.\n"
      "  sudo nvme_latency --print=summary   # the privileged collector\n"
      "  nvme_latency_web [--port=8080]      # the dashboard, as a regular user\n"
      "  nvme_latency_web --fake             # simulated data");
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  absl::Status status = nvme_bpf::Run();
  if (!status.ok()) {
    std::cerr << "nvme_latency_web: " << status << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
