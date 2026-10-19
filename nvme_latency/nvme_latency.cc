#include <unistd.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/flags.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "histogram.h"
#include "nvme_latency/bpf_latency_source.h"
#include "nvme_latency/fake_latency_source.h"
#include "nvme_latency/latency_json.h"
#include "nvme_latency/latency_source.h"
#include "nvme_latency/latency_store.h"
#include "nvme_latency/snapshot_file.h"

/*
Program used to monitor NVMe request latency.
By monitoring the IO latency at the NVMe driver layer we can isolate problem
sources between the device and the rest of the storage stack layers.

This is the privileged half of the tooling: it injects the BPF program, prints
the histograms and exports them to a snapshot file (--snapshot_path) that the
unprivileged `nvme_latency_web` dashboard reads.

Useful flags / settings:
* --ctrl_id=X. Monitor the latency only for the controller X.
* --lat_min_us=X. Sets the minimum latency to be considered for the histogram
  buckets. This allows to have more granularity around the specified value.
* --split_size. If set the histograms are split by size classes:
  <=16KiB, (16KiB,64KiB], >64KiB
* --lbs512. If set, the size classes are computed assuming 512 byte logical
  block size. By default 4KiB logical block size is assumed.
* --print=full|summary|none. Full histograms (default), one line per
  controller/opcode, or nothing.

bazel build -c opt //nvme_latency && \
sudo $(pwd)/bazel-bin/nvme_latency/nvme_latency

# Example usage:
bazel build //nvme_latency && \
sudo $(pwd)/bazel-bin/nvme_latency/nvme_latency --ctrl_id=0 --split_size \
  --lat_min_us=65

# Home nvme3
bazel build //nvme_latency && \
sudo $(pwd)/bazel-bin/nvme_latency/nvme_latency --ctrl_id=3 --split_size \
  --lat_min_us=65

# Home generate 300000 IO.
fio --name=read_lat_1 --thread=1   --ioengine=libaio --size=1200000K \
  --filesize=100% --direct=1 --randrepeat=0 --norandommap=1 \
  --filename=/dev/nvme3n1   --rw=randread --iodepth=1 --bs=4K

# Start with BPF tracing
bazel build //nvme_latency && \
sudo $(pwd)/bazel-bin/nvme_latency/nvme_latency --bpf_trace
cat /sys/kernel/tracing/trace_pipe

# With the web dashboard (the dashboard runs as a regular user):
sudo $(pwd)/bazel-bin/nvme_latency/nvme_latency --print=summary &
$(pwd)/bazel-bin/nvme_latency/nvme_latency_web

Improvement opportunities:
* Cleanup old entries in the in-flight command map.
https://docs.ebpf.io/linux/helper-function/bpf_timer_set_callback/
* Split each bucket to increase the number of buckets
* Print exclusive and total percentiles within the histogram
* Query the namespace block sizes and supply them to the BPF to filter sizes
correctly
* Print one percent lows and point one percent lows latency
* Add the ability to skip the latency measurements if the in-flight command
count or in-flight byte count exceeds a certain threshold
*/

ABSL_FLAG(int, ctrl_id, -1,
          "NVMe controller ID to filter on, -1 for all controllers");
ABSL_FLAG(int, nsid, -1, "NVMe namespace ID to filter on, -1 for all.");

ABSL_FLAG(int, lat_min_us, -1,
          "The minimum histogram latency to be considered. Provides more "
          "granularity around this value.");
ABSL_FLAG(int, lat_shift, -1,
          "log2 of the first histogram bucket size in us.");

ABSL_FLAG(bool, split_size, false, "If set splits the histograms by size");

ABSL_FLAG(bool, bpf_trace, false,
          "If set will load a program that includes bpf_printk. Requires a "
          "kernel built with CONFIG_TRACING and CONFIG_BPF_EVENTS. To display "
          "the events cat /sys/kernel/debug/tracing/trace_pipe");

ABSL_FLAG(bool, lbs512, false,
          "Compute size classes assuming 512 byte logical blocks instead of "
          "4KiB.");

ABSL_FLAG(std::string, print, "full",
          "What to print every interval: 'full' histograms, a one line "
          "'summary' per controller and opcode, or 'none'.");
ABSL_FLAG(int, interval_ms, 1000, "How often to read the histograms.");
ABSL_FLAG(std::string, snapshot_path, nvme_bpf::kDefaultSnapshotPath,
          "Where to export the histograms for nvme_latency_web (a world "
          "readable file, replaced atomically every interval). Empty to "
          "disable.");
ABSL_FLAG(bool, fake, false,
          "Simulate NVMe traffic instead of loading the BPF program. Does not "
          "require root, for testing --snapshot_path and nvme_latency_web.");

namespace nvme_bpf {
namespace {

volatile std::sig_atomic_t g_exiting = 0;
void HandleSignal(int) { g_exiting = 1; }

std::string SizeClassLabel(const HistKey& key) {
  switch (key.size_class) {
    case 0:
      return "<=16KiB";
    case 1:
      return "(16KiB, 64KiB]";
    default:
      return "(64KiB, inf)";
  }
}

// The format of the original nvme_latency output.
void PrintFull(const Snapshot& snapshot) {
  std::cout << "=====================" << std::endl;
  if (snapshot.hists.empty()) {
    std::cout << "No entries in histogram map." << std::endl;
    return;
  }
  for (const auto& [key, hist] : snapshot.hists) {
    std::cout << "key: ctrl_id=" << key.ctrl_id
              << ", opcode=" << static_cast<int>(key.opcode) << " "
              << OpcodeName(key.opcode);
    if (snapshot.info.split_size) std::cout << ", " << SizeClassLabel(key);
    std::cout << std::endl;

    std::array<u64, LATENCY_MAX_SLOTS + 1> slots;
    std::copy(hist.slots.begin(), hist.slots.end(), slots.begin());
    Histogram h;
    h.lat_min_us = static_cast<int>(snapshot.info.params.lat_min_us);
    h.lat_shift = snapshot.info.params.lat_shift;
    h.max_slots = snapshot.info.params.max_slots;
    h.slots = slots.data();
    h.total_count = hist.total_count;
    h.total_sum = hist.total_sum_us;
    if (absl::Status s = PrintHistogram(h); !s.ok()) {
      std::cerr << "Failed to print histogram: " << s << std::endl;
    }
  }
}

std::string FormatUs(double us) {
  if (!std::isfinite(us)) return "-";
  if (us < 1000) return absl::StrFormat("%.0fus", us);
  if (us < 1e6) return absl::StrFormat("%.2fms", us / 1e3);
  return absl::StrFormat("%.2fs", us / 1e6);
}

std::string FormatRate(double v) {
  if (v < 1000) return absl::StrFormat("%.0f", v);
  if (v < 1e6) return absl::StrFormat("%.1fk", v / 1e3);
  return absl::StrFormat("%.2fM", v / 1e6);
}

// One line per histogram with the statistics of the last interval.
void PrintSummary(const std::optional<Snapshot>& prev, const Snapshot& cur) {
  if (!prev.has_value()) {
    std::cout << "Collecting, the first summary is printed in one interval."
              << std::endl;
    return;
  }
  const std::vector<BucketBounds> bounds =
      DisplayBucketBounds(cur.info.params);
  const double dt = absl::ToDoubleSeconds(cur.time - prev->time);
  std::cout << absl::FormatTime("%H:%M:%S", cur.time, absl::LocalTimeZone());
  if (cur.hists.empty()) std::cout << "  (no NVMe completions yet)";
  std::cout << std::endl;
  for (const auto& [key, hist] : cur.hists) {
    CumulativeHist base;
    for (const auto& [prev_key, prev_hist] : prev->hists) {
      if (prev_key == key) base = prev_hist;
    }
    if (hist.total_count < base.total_count) base = CumulativeHist{};
    const DisplayHist a = ToDisplayHist(hist, cur.info.params.max_slots);
    const DisplayHist b = ToDisplayHist(base, cur.info.params.max_slots);
    DisplayHist delta{};
    for (int i = 0; i < kNumDisplayBuckets; ++i) {
      delta[i] = a[i] > b[i] ? a[i] - b[i] : 0;
    }
    const uint64_t count = hist.total_count - base.total_count;
    const uint64_t sum =
        hist.total_sum_us > base.total_sum_us ? hist.total_sum_us - base.total_sum_us : 0;
    std::string name = absl::StrCat("nvme", key.ctrl_id, " ", OpcodeName(key.opcode));
    if (cur.info.split_size) absl::StrAppend(&name, " ", SizeClassLabel(key));
    std::cout << absl::StrFormat(
                     "  %-28s %8s IOPS  p50 %8s  p90 %8s  p99 %8s  p99.9 %8s  "
                     "avg %8s",
                     name, FormatRate(dt > 0 ? count / dt : 0),
                     FormatUs(HistPercentile(delta, bounds, 0.5)),
                     FormatUs(HistPercentile(delta, bounds, 0.9)),
                     FormatUs(HistPercentile(delta, bounds, 0.99)),
                     FormatUs(HistPercentile(delta, bounds, 0.999)),
                     FormatUs(count ? static_cast<double>(sum) / count : NAN))
              << std::endl;
  }
}

absl::StatusOr<std::unique_ptr<LatencySource>> CreateSource(
    absl::Duration interval) {
  if (absl::GetFlag(FLAGS_fake)) {
    FakeSourceOptions options;
    if (absl::GetFlag(FLAGS_lat_min_us) >= 0) {
      options.params.lat_min_us = absl::GetFlag(FLAGS_lat_min_us);
    }
    if (absl::GetFlag(FLAGS_lat_shift) >= 0) {
      options.params.lat_shift = absl::GetFlag(FLAGS_lat_shift);
    }
    options.split_size = absl::GetFlag(FLAGS_split_size);
    options.ctrl_id_filter = absl::GetFlag(FLAGS_ctrl_id);
    options.interval = interval;
    return CreateFakeLatencySource(options);
  }
  BpfSourceOptions options;
  options.ctrl_id = absl::GetFlag(FLAGS_ctrl_id);
  options.nsid = absl::GetFlag(FLAGS_nsid);
  options.lat_min_us = absl::GetFlag(FLAGS_lat_min_us);
  options.lat_shift = absl::GetFlag(FLAGS_lat_shift);
  options.split_size = absl::GetFlag(FLAGS_split_size);
  options.lbs512 = absl::GetFlag(FLAGS_lbs512);
  options.trace = absl::GetFlag(FLAGS_bpf_trace);
  options.interval = interval;
  return CreateBpfLatencySource(options);
}

absl::Status Run() {
  const std::string print = absl::GetFlag(FLAGS_print);
  if (print != "full" && print != "summary" && print != "none") {
    return absl::InvalidArgumentError(
        absl::StrCat("--print must be full, summary or none, got: ", print));
  }
  const absl::Duration interval = absl::Milliseconds(
      std::clamp(absl::GetFlag(FLAGS_interval_ms), 100, 60000));
  const std::string snapshot_path = absl::GetFlag(FLAGS_snapshot_path);
  if (!snapshot_path.empty()) {
    if (absl::Status s = PrepareSnapshotDir(snapshot_path); !s.ok()) {
      return absl::Status(s.code(),
                          absl::StrCat(s.message(),
                                       ". Use --snapshot_path to pick another "
                                       "location or --snapshot_path= to disable."));
    }
  }

  absl::StatusOr<std::unique_ptr<LatencySource>> source = CreateSource(interval);
  if (!source.ok()) return source.status();

  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);
  std::cout << "Successfully started!" << std::endl;
  if (!snapshot_path.empty()) {
    std::cout << "Exporting histograms to " << snapshot_path
              << ", view them with: nvme_latency_web (no root needed)"
              << std::endl;
  }

  // Read on multiples of the interval so that samples align with the time
  // buckets of the dashboard graphs.
  const int64_t interval_ms = absl::ToInt64Milliseconds(interval);
  auto next_tick = [interval_ms](absl::Time now) {
    return absl::FromUnixMillis((absl::ToUnixMillis(now) / interval_ms + 1) *
                                interval_ms);
  };
  absl::Time next = next_tick(absl::Now());
  std::optional<Snapshot> prev;
  while (!g_exiting) {
    const absl::Time now = absl::Now();
    if (now < next) {
      absl::SleepFor(std::min(next - now, absl::Milliseconds(50)));
      continue;
    }
    next = next_tick(now);
    absl::StatusOr<Snapshot> snapshot = (*source)->Read();
    if (!snapshot.ok()) {
      LOG_EVERY_N_SEC(ERROR, 10)
          << "Failed to read the histograms: " << snapshot.status();
      continue;
    }
    if (!snapshot_path.empty()) {
      if (absl::Status s = WriteSnapshotFile(snapshot_path, *snapshot);
          !s.ok()) {
        LOG_EVERY_N_SEC(ERROR, 10) << "Failed to export the snapshot: " << s;
      }
    }
    if (print == "full") {
      PrintFull(*snapshot);
    } else if (print == "summary") {
      PrintSummary(prev, *snapshot);
    }
    prev = std::move(*snapshot);
  }

  std::cout << "Exiting." << std::endl;
  // Let the dashboard know right away that the collector is gone.
  if (!snapshot_path.empty()) unlink(snapshot_path.c_str());
  return absl::OkStatus();
}

}  // namespace
}  // namespace nvme_bpf

int main(int argc, char** argv) {
  absl::SetProgramUsageMessage(
      "Monitors NVMe request latency with a BPF program (requires root).\n"
      "  sudo nvme_latency [--ctrl_id=N] [--split_size] [--print=summary]\n"
      "The histograms are exported to --snapshot_path for nvme_latency_web.");
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  absl::Status status = nvme_bpf::Run();
  if (!status.ok()) {
    std::cerr << status << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
