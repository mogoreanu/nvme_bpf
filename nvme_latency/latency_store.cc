#include "nvme_latency/latency_store.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <limits>
#include <vector>

#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "histogram.bpf.h"

namespace nvme_bpf {
namespace {

int64_t FloorDiv(int64_t a, int64_t b) {
  int64_t q = a / b;
  if ((a % b != 0) && ((a < 0) != (b < 0))) --q;
  return q;
}

// Accumulates (merges) samples.
struct Accumulator {
  DisplayHist hist{};
  uint64_t count = 0;
  uint64_t sum_us = 0;
  int64_t duration_ms = 0;
  bool has_data = false;

  template <typename SampleT>
  void Add(const SampleT& s) {
    for (int i = 0; i < kNumDisplayBuckets; ++i) hist[i] += s.delta[i];
    count += s.count;
    sum_us += s.sum_us;
    duration_ms += s.duration_ms;
    has_data = true;
  }
};

LatencyStats ToStats(const DisplayHist& hist, uint64_t count, uint64_t sum_us,
                     double duration_s, bool has_data,
                     const std::vector<BucketBounds>& bounds) {
  LatencyStats stats;
  stats.count = count;
  stats.sum_us = sum_us;
  stats.overflow = hist[kOverflowBucket];
  stats.duration_s = duration_s;
  if (!has_data) return stats;
  if (duration_s > 0) stats.iops = static_cast<double>(count) / duration_s;
  if (count > 0) {
    stats.avg_us = static_cast<double>(sum_us) / static_cast<double>(count);
  }
  stats.p50_us = HistPercentile(hist, bounds, 0.50);
  stats.p90_us = HistPercentile(hist, bounds, 0.90);
  stats.p99_us = HistPercentile(hist, bounds, 0.99);
  stats.p999_us = HistPercentile(hist, bounds, 0.999);
  return stats;
}

LatencyStats ToStats(const Accumulator& acc,
                     const std::vector<BucketBounds>& bounds) {
  return ToStats(acc.hist, acc.count, acc.sum_us, acc.duration_ms / 1000.0,
                 acc.has_data, bounds);
}

}  // namespace

std::vector<BucketBounds> DisplayBucketBounds(const HistogramParams& p) {
  std::vector<BucketBounds> bounds(kNumDisplayBuckets);
  // Below min.
  bounds[0] = {static_cast<double>(
                   bpf_bucket_low(p.max_slots, p.lat_min_us, p.lat_shift,
                                  p.max_slots)),
               static_cast<double>(bpf_bucket_high(
                   p.max_slots, p.lat_min_us, p.lat_shift, p.max_slots))};
  for (int slot = 0; slot < p.max_slots; ++slot) {
    bounds[slot + 1] = {
        static_cast<double>(
            bpf_bucket_low(slot, p.lat_min_us, p.lat_shift, p.max_slots)),
        static_cast<double>(
            bpf_bucket_high(slot, p.lat_min_us, p.lat_shift, p.max_slots))};
  }
  bounds[kOverflowBucket] = {bounds[kOverflowBucket - 1].high_us,
                             std::numeric_limits<double>::infinity()};
  return bounds;
}

DisplayHist ToDisplayHist(const CumulativeHist& hist, int max_slots) {
  DisplayHist out{};
  uint64_t slot_sum = 0;
  out[0] = hist.slots[max_slots];
  slot_sum += hist.slots[max_slots];
  for (int slot = 0; slot < max_slots; ++slot) {
    out[slot + 1] = hist.slots[slot];
    slot_sum += hist.slots[slot];
  }
  // The BPF program increments total_count before the slot, so a concurrent
  // read may observe total_count slightly ahead of the slots. Never report a
  // negative overflow.
  out[kOverflowBucket] =
      hist.total_count > slot_sum ? hist.total_count - slot_sum : 0;
  return out;
}

double HistPercentile(const DisplayHist& hist,
                      const std::vector<BucketBounds>& bounds,
                      double fraction) {
  uint64_t total = 0;
  for (uint64_t c : hist) total += c;
  if (total == 0) return kNaN;
  fraction = std::clamp(fraction, 0.0, 1.0);
  const double rank = fraction * static_cast<double>(total);
  uint64_t cumulative = 0;
  int last_nonempty = 0;
  for (int i = 0; i < kNumDisplayBuckets; ++i) {
    if (hist[i] == 0) continue;
    last_nonempty = i;
    if (static_cast<double>(cumulative + hist[i]) >= rank) {
      if (i == kOverflowBucket) return bounds[i].low_us;
      const double within = (rank - static_cast<double>(cumulative)) /
                            static_cast<double>(hist[i]);
      return bounds[i].low_us +
             std::clamp(within, 0.0, 1.0) *
                 (bounds[i].high_us - bounds[i].low_us);
    }
    cumulative += hist[i];
  }
  return last_nonempty == kOverflowBucket ? bounds[last_nonempty].low_us
                                          : bounds[last_nonempty].high_us;
}

absl::Duration ChooseStep(absl::Duration window, int max_points,
                          absl::Duration min_step) {
  static constexpr int64_t kNiceStepsMs[] = {
      100,    200,    250,     500,     1000,    2000,    5000,
      10000,  15000,  30000,   60000,   120000,  300000,  600000,
      900000, 1800000, 3600000, 7200000, 21600000, 86400000};
  const int64_t window_ms = std::max<int64_t>(1, absl::ToInt64Milliseconds(window));
  max_points = std::max(1, max_points);
  const int64_t needed_ms = std::max<int64_t>(
      (window_ms + max_points - 1) / max_points,
      std::max<int64_t>(1, absl::ToInt64Milliseconds(min_step)));
  for (int64_t step : kNiceStepsMs) {
    if (step >= needed_ms) return absl::Milliseconds(step);
  }
  return absl::Milliseconds(needed_ms);
}

LatencyStore::LatencyStore(HistogramParams params, absl::Duration history,
                           absl::Time start_time, bool baseline_first_snapshot)
    : params_(params),
      bounds_(DisplayBucketBounds(params)),
      history_(history),
      start_time_(start_time),
      baseline_first_snapshot_(baseline_first_snapshot),
      last_time_(start_time) {}

void LatencyStore::Add(const Snapshot& snapshot) {
  absl::MutexLock lock(mu_);
  if (snapshot.time <= last_time_) return;

  if (baseline_first_snapshot_ && num_snapshots_ == 0) {
    for (const auto& [key, cumulative] : snapshot.hists) {
      keys_[key].last = cumulative;
    }
    last_time_ = snapshot.time;
    ++num_snapshots_;
    return;
  }

  const int64_t end_ms = absl::ToUnixMillis(snapshot.time);
  const int64_t duration_ms =
      absl::ToInt64Milliseconds(snapshot.time - last_time_);

  for (const auto& [key, cumulative] : snapshot.hists) {
    KeyState& state = keys_[key];
    CumulativeHist base = state.last;
    if (cumulative.total_count < base.total_count) {
      // The source was reset, e.g. the BPF program was reloaded.
      base = CumulativeHist{};
    }
    const DisplayHist current_hist =
        ToDisplayHist(cumulative, params_.max_slots);
    const DisplayHist base_hist = ToDisplayHist(base, params_.max_slots);

    Sample sample;
    sample.end_ms = end_ms;
    sample.duration_ms = duration_ms;
    for (int i = 0; i < kNumDisplayBuckets; ++i) {
      sample.delta[i] = current_hist[i] > base_hist[i]
                            ? current_hist[i] - base_hist[i]
                            : 0;
    }
    sample.count = cumulative.total_count - base.total_count;
    sample.sum_us = cumulative.total_sum_us > base.total_sum_us
                        ? cumulative.total_sum_us - base.total_sum_us
                        : 0;
    state.last = cumulative;
    state.samples.push_back(sample);
  }

  const int64_t cutoff_ms = end_ms - absl::ToInt64Milliseconds(history_);
  for (auto& [key, state] : keys_) {
    while (!state.samples.empty() && state.samples.front().end_ms <= cutoff_ms) {
      state.samples.pop_front();
    }
  }
  last_time_ = snapshot.time;
  ++num_snapshots_;
}

Report LatencyStore::Query(const QueryOptions& options, absl::Time now) const {
  Report report;
  report.now_ms = absl::ToUnixMillis(now);
  report.window_ms =
      std::max<int64_t>(1000, absl::ToInt64Milliseconds(options.window));
  report.step_ms = absl::ToInt64Milliseconds(ChooseStep(
      absl::Milliseconds(report.window_ms), options.max_points,
      options.min_step));
  report.start_ms = absl::ToUnixMillis(start_time_);

  const int64_t step_ms = report.step_ms;
  const int64_t window_start_ms = report.now_ms - report.window_ms;
  const int64_t recent_start_ms =
      report.now_ms - absl::ToInt64Milliseconds(options.recent);
  const int64_t first_ms = FloorDiv(window_start_ms, step_ms) * step_ms;
  const int64_t last_ms = FloorDiv(report.now_ms, step_ms) * step_ms;
  const int num_points = static_cast<int>((last_ms - first_ms) / step_ms) + 1;
  report.t_ms.resize(num_points);
  for (int i = 0; i < num_points; ++i) report.t_ms[i] = first_ms + i * step_ms;

  absl::MutexLock lock(mu_);
  report.num_snapshots = num_snapshots_;
  report.last_sample_ms =
      num_snapshots_ > 0 ? absl::ToUnixMillis(last_time_) : 0;

  for (const auto& [key, state] : keys_) {
    SeriesReport series;
    series.key = key;

    std::vector<Accumulator> points(num_points);
    Accumulator window_acc;
    Accumulator recent_acc;
    for (auto it = state.samples.rbegin(); it != state.samples.rend(); ++it) {
      const Sample& s = *it;
      if (s.end_ms <= window_start_ms) break;
      if (s.end_ms > report.now_ms) continue;
      window_acc.Add(s);
      if (s.end_ms > recent_start_ms) recent_acc.Add(s);
      // Bucket by the middle of the sample interval, which makes the
      // assignment robust against small jitter of the sampling time.
      const int64_t mid_ms = s.end_ms - s.duration_ms / 2;
      const int64_t idx = std::clamp<int64_t>(
          FloorDiv(mid_ms - first_ms, step_ms), 0, num_points - 1);
      points[idx].Add(s);
    }

    for (std::vector<double>* v :
         {&series.p50_us, &series.p90_us, &series.p99_us, &series.p999_us,
          &series.avg_us, &series.iops}) {
      v->reserve(num_points);
    }
    for (const Accumulator& acc : points) {
      const LatencyStats stats = ToStats(acc, bounds_);
      series.p50_us.push_back(stats.p50_us);
      series.p90_us.push_back(stats.p90_us);
      series.p99_us.push_back(stats.p99_us);
      series.p999_us.push_back(stats.p999_us);
      series.avg_us.push_back(stats.avg_us);
      series.iops.push_back(stats.iops);
    }

    series.window = ToStats(window_acc, bounds_);
    series.window_hist = window_acc.hist;
    series.recent = ToStats(recent_acc, bounds_);

    series.lifetime_hist = ToDisplayHist(state.last, params_.max_slots);
    series.lifetime = ToStats(
        series.lifetime_hist, state.last.total_count, state.last.total_sum_us,
        absl::ToDoubleSeconds(last_time_ - start_time_),
        /*has_data=*/true, bounds_);

    report.series.push_back(std::move(series));
  }
  return report;
}

}  // namespace nvme_bpf
