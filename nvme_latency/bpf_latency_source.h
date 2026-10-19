#ifndef NVME_BPF_BPF_LATENCY_SOURCE_H_
#define NVME_BPF_BPF_LATENCY_SOURCE_H_

#include <memory>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {

struct BpfSourceOptions {
  int ctrl_id = -1;     // -1 for all controllers.
  int nsid = -1;        // -1 for all namespaces.
  int lat_min_us = -1;  // -1 for the BPF program default.
  int lat_shift = -1;   // -1 for the BPF program default.
  bool split_size = false;
  bool lbs512 = false;
  // Load the program variant that logs every request with bpf_printk.
  bool trace = false;
  // Reported in the snapshot info.
  absl::Duration interval = absl::Seconds(1);
};

// Loads and attaches the `nvme_latency.bpf.c` program to the NVMe tracepoints.
// Requires root (CAP_BPF + CAP_PERFMON and access to tracefs). The program is
// detached when the returned source is destroyed.
absl::StatusOr<std::unique_ptr<LatencySource>> CreateBpfLatencySource(
    const BpfSourceOptions& options);

}  // namespace nvme_bpf

#endif  // NVME_BPF_BPF_LATENCY_SOURCE_H_
