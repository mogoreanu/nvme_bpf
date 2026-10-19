#ifndef NVME_BPF_SNAPSHOT_FILE_H_
#define NVME_BPF_SNAPSHOT_FILE_H_

// Snapshot files hand the latency histograms from the privileged collector
// (`sudo nvme_latency`, which owns the BPF program) to the unprivileged
// dashboard (`nvme_latency_web`).
//
// The collector periodically and atomically replaces the file (write to a
// temporary file + rename), so readers always see a complete snapshot. The
// collector only writes: it does not parse any input or listen on any socket.
//
// The format is line based text, readable with `cat`:
//
//   nvme_latency_snapshot 1
//   source bpf
//   time_us 1792430000123456
//   start_us 1792429000000000
//   interval_us 1000000
//   lat_min_us 20
//   lat_shift 0
//   max_slots 27
//   split_size 0
//   ctrl_id_filter -1
//   nsid_filter -1
//   hist <ctrl_id> <opcode> <size_class> <total_count> <total_sum_us> \
//        <slot 0> ... <slot max_slots>
//   end
//
// Slots have the meaning of `struct latency_hist::slots`. Unknown keys are
// ignored by readers.

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {

inline constexpr char kDefaultSnapshotPath[] = "/run/nvme_latency/snapshot";

std::string SerializeSnapshot(const Snapshot& snapshot);
absl::StatusOr<Snapshot> ParseSnapshot(absl::string_view text);

// Creates the parent directory of `path` if needed (a single level, mode
// 0755). When running as root, refuses directories that other users could
// tamper with.
absl::Status PrepareSnapshotDir(const std::string& path);

// Atomically replaces `path` with the snapshot. The file is world readable.
absl::Status WriteSnapshotFile(const std::string& path,
                               const Snapshot& snapshot);

absl::StatusOr<Snapshot> ReadSnapshotFile(const std::string& path);

struct SnapshotFileSourceOptions {
  std::string path = kDefaultSnapshotPath;
  // Snapshots older than max(max_age, 5 * collector interval) are reported as
  // errors (the collector probably stopped).
  absl::Duration max_age = absl::Seconds(5);
  absl::Time (*now)() = &absl::Now;
};

// A LatencySource reading the snapshots written by the collector.
std::unique_ptr<LatencySource> CreateSnapshotFileSource(
    const SnapshotFileSourceOptions& options);

}  // namespace nvme_bpf

#endif  // NVME_BPF_SNAPSHOT_FILE_H_
