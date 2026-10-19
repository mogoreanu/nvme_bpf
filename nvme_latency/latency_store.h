#ifndef NVME_BPF_LATENCY_STORE_H_
#define NVME_BPF_LATENCY_STORE_H_

#include <array>
#include <cstdint>
#include <deque>
#include <limits>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/btree_map.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {

// Histograms are exposed in "display order", sorted by latency:
//   [0]                  latencies below lat_min_us.
//   [1 .. max_slots]     BPF slots 0 .. max_slots-1.
//   [max_slots + 1]      latencies above the largest slot (overflow).
inline constexpr int kNumDisplayBuckets = LATENCY_MAX_SLOTS + 2;
inline constexpr int kOverflowBucket = kNumDisplayBuckets - 1;
using DisplayHist = std::array<uint64_t, kNumDisplayBuckets>;

struct BucketBounds {
  double low_us = 0;
  double high_us = 0;  // +infinity for the overflow bucket.
};

// Bounds for every display bucket.
std::vector<BucketBounds> DisplayBucketBounds(const HistogramParams& params);

// Converts a cumulative BPF histogram into display order.
DisplayHist ToDisplayHist(const CumulativeHist& hist, int max_slots);

// Estimates the `fraction` (0..1) percentile of the histogram, interpolating
// linearly within the bucket. Values in the overflow bucket are reported as
// the overflow bucket's lower bound. Returns NaN for an empty histogram.
double HistPercentile(const DisplayHist& hist,
                      const std::vector<BucketBounds>& bounds, double fraction);

inline constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();

// Summary statistics over an interval.
struct LatencyStats {
  uint64_t count = 0;
  uint64_t sum_us = 0;
  uint64_t overflow = 0;
  double duration_s = 0;
  double iops = kNaN;
  double avg_us = kNaN;
  double p50_us = kNaN;
  double p90_us = kNaN;
  double p99_us = kNaN;
  double p999_us = kNaN;
};

// Time series and summaries for one histogram key.
struct SeriesReport {
  HistKey key;
  // Aligned with Report::t_ms. NaN when there is no data for that point.
  std::vector<double> p50_us, p90_us, p99_us, p999_us, avg_us, iops;
  LatencyStats recent;    // Over QueryOptions::recent.
  LatencyStats window;    // Over QueryOptions::window.
  LatencyStats lifetime;  // Since the store was created.
  DisplayHist window_hist{};
  DisplayHist lifetime_hist{};
};

struct Report {
  int64_t now_ms = 0;
  int64_t window_ms = 0;
  int64_t step_ms = 0;
  int64_t start_ms = 0;          // When the store started collecting.
  int64_t last_sample_ms = 0;    // 0 if no snapshot was added yet.
  int64_t num_snapshots = 0;
  // Start time of each point (unix milliseconds), spaced by step_ms.
  std::vector<int64_t> t_ms;
  std::vector<SeriesReport> series;  // Sorted by key.
};

struct QueryOptions {
  absl::Duration window = absl::Minutes(5);
  // Upper bound on the number of points per series; consecutive samples are
  // merged to stay within the limit.
  int max_points = 600;
  // The smallest step, normally the sampling interval.
  absl::Duration min_step = absl::Seconds(1);
  // Interval for the "recent" headline statistics.
  absl::Duration recent = absl::Seconds(5);
};

// Picks a "nice" step (e.g. 1s, 2s, 5s, 10s, ...) so that `window / step` is
// at most `max_points` and step >= min_step.
absl::Duration ChooseStep(absl::Duration window, int max_points,
                          absl::Duration min_step);

// Accumulates snapshots of cumulative histograms and keeps a bounded history
// of per-interval delta histograms. Percentiles for any time range are
// computed by merging the delta histograms of that range, which is exact up
// to the bucket resolution (as opposed to averaging percentiles).
//
// Thread-safe.
class LatencyStore {
 public:
  // `start_time` is when the source counters started. With
  // `baseline_first_snapshot`, the first snapshot only establishes the
  // baseline for the deltas, which is needed when attaching to a source that
  // has been counting for a while (its first delta would span its whole
  // lifetime).
  LatencyStore(HistogramParams params, absl::Duration history,
               absl::Time start_time, bool baseline_first_snapshot = false);

  const HistogramParams& params() const { return params_; }
  const std::vector<BucketBounds>& bounds() const { return bounds_; }

  // Adds a snapshot. Snapshots must be added in increasing time order; older
  // or equal timestamps are ignored.
  void Add(const Snapshot& snapshot);

  Report Query(const QueryOptions& options, absl::Time now) const;

 private:
  // The change of a histogram over one sampling interval.
  struct Sample {
    int64_t end_ms = 0;
    int64_t duration_ms = 0;
    DisplayHist delta{};
    uint64_t count = 0;
    uint64_t sum_us = 0;
  };
  struct KeyState {
    CumulativeHist last;
    std::deque<Sample> samples;
  };

  const HistogramParams params_;
  const std::vector<BucketBounds> bounds_;
  const absl::Duration history_;
  const absl::Time start_time_;
  const bool baseline_first_snapshot_;

  mutable absl::Mutex mu_;
  absl::btree_map<HistKey, KeyState> keys_ ABSL_GUARDED_BY(mu_);
  absl::Time last_time_ ABSL_GUARDED_BY(mu_);
  int64_t num_snapshots_ ABSL_GUARDED_BY(mu_) = 0;
};

}  // namespace nvme_bpf

#endif  // NVME_BPF_LATENCY_STORE_H_
