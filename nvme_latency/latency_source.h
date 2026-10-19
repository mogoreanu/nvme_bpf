#ifndef NVME_BPF_LATENCY_SOURCE_H_
#define NVME_BPF_LATENCY_SOURCE_H_

#include <array>
#include <compare>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "nvme_latency/nvme_latency.h"

namespace nvme_bpf {

// Describes how latency values (in microseconds) are mapped to histogram
// slots. See `histogram.bpf.h` for the mapping functions.
struct HistogramParams {
  uint64_t lat_min_us = 20;
  int lat_shift = 0;
  int max_slots = LATENCY_MAX_SLOTS;

  friend bool operator==(const HistogramParams&,
                         const HistogramParams&) = default;
};

// Identifies one latency histogram: a (controller, opcode, size class) tuple.
struct HistKey {
  uint32_t ctrl_id = 0;
  uint8_t opcode = 0;
  uint8_t size_class = 0;

  friend auto operator<=>(const HistKey&, const HistKey&) = default;
  friend bool operator==(const HistKey&, const HistKey&) = default;

  template <typename H>
  friend H AbslHashValue(H h, const HistKey& k) {
    return H::combine(std::move(h), k.ctrl_id, k.opcode, k.size_class);
  }
};

// A cumulative (since start) latency histogram, as maintained by the BPF
// program in `struct latency_hist`.
//   slots[0..max_slots-1]: latency buckets, see bpf_get_bucket().
//   slots[max_slots]: latencies below `lat_min_us`.
//   total_count - sum(slots): latencies above the largest bucket.
struct CumulativeHist {
  std::array<uint64_t, LATENCY_MAX_SLOTS + 1> slots{};
  uint64_t total_sum_us = 0;
  uint64_t total_count = 0;

  friend bool operator==(const CumulativeHist&,
                         const CumulativeHist&) = default;
};

// Describes how the histograms were collected.
struct SourceInfo {
  std::string source;      // E.g. "bpf" or "fake".
  HistogramParams params;
  absl::Time start_time;   // When the counters started (were zero).
  absl::Duration interval = absl::Seconds(1);  // Sampling interval.
  bool split_size = false;
  int ctrl_id_filter = -1;
  int nsid_filter = -1;

  friend bool operator==(const SourceInfo&, const SourceInfo&) = default;
};

// The state of all the histograms at a point in time.
struct Snapshot {
  absl::Time time;
  SourceInfo info;
  std::vector<std::pair<HistKey, CumulativeHist>> hists;  // Sorted by key.
};

// A source of cumulative latency histograms, e.g. the BPF program injected in
// the kernel, a snapshot file written by it, or a simulator.
class LatencySource {
 public:
  virtual ~LatencySource() = default;

  // Short human readable description of the source, e.g. "bpf".
  virtual std::string name() const = 0;

  // Reads the current cumulative state of all histograms.
  virtual absl::StatusOr<Snapshot> Read() = 0;
};

}  // namespace nvme_bpf

#endif  // NVME_BPF_LATENCY_SOURCE_H_
