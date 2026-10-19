#ifndef NVME_BPF_FAKE_LATENCY_SOURCE_H_
#define NVME_BPF_FAKE_LATENCY_SOURCE_H_

#include <cstdint>
#include <memory>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {

struct FakeSourceOptions {
  HistogramParams params;
  uint64_t seed = 1;
  // Simulate the --split_size size classes.
  bool split_size = false;
  // Only simulate this controller, -1 for all.
  int ctrl_id_filter = -1;
  // Reported in the snapshot info.
  absl::Duration interval = absl::Seconds(1);
  // Time source, overridable for tests.
  absl::Time (*now)() = &absl::Now;
};

// A source that simulates NVMe traffic on a couple of controllers, with
// diurnal-ish load variation, latency growing with load and periodic latency
// spikes (e.g. garbage collection stalls). Useful for developing the UI
// without root privileges.
std::unique_ptr<LatencySource> CreateFakeLatencySource(
    const FakeSourceOptions& options);

}  // namespace nvme_bpf

#endif  // NVME_BPF_FAKE_LATENCY_SOURCE_H_
