#include "nvme_latency/bpf_latency_source.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/globals.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "nvme_latency/latency_source.h"
#include "nvme_latency/nvme_latency.h"
#include "nvme_latency/nvme_latency_bpf.skel.h"
#include "nvme_latency/nvme_latency_vlog_bpf.skel.h"

namespace nvme_bpf {
namespace {

int LibbpfPrint(enum libbpf_print_level level, const char* format,
                va_list args) {
  // Like the original tools: everything with --stderrthreshold=0 or -v=1,
  // otherwise only warnings.
  const bool verbose =
      absl::StderrThreshold() <= absl::LogSeverityAtLeast::kInfo ||
      ABSL_VLOG_IS_ON(1);
  if (level != LIBBPF_WARN && !verbose) return 0;
  char buffer[1024];
  const int n = vsnprintf(buffer, sizeof(buffer), format, args);
  absl::string_view message = absl::StripTrailingAsciiWhitespace(buffer);
  if (level == LIBBPF_WARN) {
    LOG(WARNING) << "libbpf: " << message;
  } else {
    LOG(INFO) << "libbpf: " << message;
  }
  return n;
}

// TSkel is one of the generated skeletons of nvme_latency.bpf.c.
template <typename TSkel>
class BpfLatencySource : public LatencySource {
 public:
  explicit BpfLatencySource(TSkel* skel) : skel_(skel) {}

  ~BpfLatencySource() override {
    if (attached_) TSkel::detach(skel_);
    TSkel::destroy(skel_);
  }

  absl::Status Init(const BpfSourceOptions& options) {
    if (options.ctrl_id >= 0) skel_->rodata->filter_ctrl_id = options.ctrl_id;
    if (options.nsid >= 0) skel_->rodata->filter_nsid = options.nsid;
    if (options.lat_min_us >= 0) {
      skel_->rodata->latency_min = options.lat_min_us;
    }
    if (options.lat_shift >= 0) {
      skel_->rodata->latency_shift = options.lat_shift;
    }
    if (options.split_size) {
      // Size classes: <=16KiB, (16KiB, 64KiB], >64KiB.
      const int blocks_per_4k = options.lbs512 ? 8 : 1;
      skel_->rodata->class1_size_nlb = 4 * blocks_per_4k;
      skel_->rodata->class2_size_nlb = 16 * blocks_per_4k;
    }
    info_.source = "bpf";
    info_.params.lat_min_us = skel_->rodata->latency_min;
    info_.params.lat_shift = static_cast<int>(skel_->rodata->latency_shift);
    info_.params.max_slots = LATENCY_MAX_SLOTS;
    info_.interval = options.interval;
    info_.split_size = options.split_size;
    info_.ctrl_id_filter = options.ctrl_id;
    info_.nsid_filter = options.nsid;

    int err = TSkel::load(skel_);
    if (err) {
      return absl::PermissionDeniedError(absl::StrCat(
          "Failed to load and verify the BPF program (", strerror(-err),
          "). Loading BPF programs requires root, or CAP_BPF + CAP_PERFMON."));
    }
    // The histograms are created empty on load, start counting from here.
    info_.start_time = absl::Now();
    err = TSkel::attach(skel_);
    if (err) {
      return absl::UnavailableError(absl::StrCat(
          "Failed to attach the BPF program to the nvme tracepoints (",
          strerror(-err), "). Is the nvme_core module loaded?"));
    }
    attached_ = true;
    return absl::OkStatus();
  }

  std::string name() const override { return "bpf"; }

  absl::StatusOr<Snapshot> Read() override {
    const int fd = bpf_map__fd(skel_->maps.hists);
    if (fd < 0) {
      return absl::InternalError(
          absl::StrCat("BPF latency histogram map error, fd=", fd));
    }
    Snapshot snapshot;
    snapshot.time = absl::Now();
    snapshot.info = info_;

    latency_hist_key key = {};
    latency_hist_key next_key = {};
    const latency_hist_key* prev = nullptr;  // nullptr returns the first key.
    int rc;
    while ((rc = bpf_map_get_next_key(fd, prev, &next_key)) == 0) {
      latency_hist value;
      if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
        CumulativeHist hist;
        std::copy(std::begin(value.slots), std::end(value.slots),
                  hist.slots.begin());
        hist.total_sum_us = value.total_sum;
        hist.total_count = value.total_count;
        snapshot.hists.emplace_back(
            HistKey{next_key.ctrl_id, next_key.opcode, next_key.size_class},
            hist);
      }
      key = next_key;
      prev = &key;
    }
    if (rc != -ENOENT) {
      return absl::ErrnoToStatus(-rc, "Iterating the BPF histogram map");
    }
    std::sort(snapshot.hists.begin(), snapshot.hists.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    return snapshot;
  }

 private:
  TSkel* const skel_;
  SourceInfo info_;
  bool attached_ = false;
};

template <typename TSkel>
absl::StatusOr<std::unique_ptr<LatencySource>> Create(
    const BpfSourceOptions& options) {
  TSkel* skel = TSkel::open();
  if (skel == nullptr) {
    return absl::InternalError(
        absl::StrCat("Failed to open the BPF skeleton: ", strerror(errno)));
  }
  auto source = std::make_unique<BpfLatencySource<TSkel>>(skel);
  if (absl::Status status = source->Init(options); !status.ok()) {
    return status;
  }
  return source;
}

}  // namespace

absl::StatusOr<std::unique_ptr<LatencySource>> CreateBpfLatencySource(
    const BpfSourceOptions& options) {
  libbpf_set_print(LibbpfPrint);
  if (options.trace) {
    return Create<nvme_latency_vlog_bpf>(options);
  } else {
    return Create<nvme_latency_bpf>(options);
  }
}

}  // namespace nvme_bpf
