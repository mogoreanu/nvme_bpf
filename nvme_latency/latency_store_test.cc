#include "nvme_latency/latency_store.h"

#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>

#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {
namespace {

using ::testing::DoubleNear;
using ::testing::SizeIs;

const absl::Time kStart = absl::FromUnixSeconds(1'700'000'000);

TEST(DisplayBucketBoundsTest, DefaultParams) {
  HistogramParams params;  // min=20us, shift=0.
  std::vector<BucketBounds> b = DisplayBucketBounds(params);
  ASSERT_THAT(b, SizeIs(kNumDisplayBuckets));
  // Below min.
  EXPECT_EQ(b[0].low_us, 0);
  EXPECT_EQ(b[0].high_us, 20);
  // Slot 0: [min, min + 1).
  EXPECT_EQ(b[1].low_us, 20);
  EXPECT_EQ(b[1].high_us, 21);
  // Slot 1: [min + 1, min + 2), slot 2: [min + 2, min + 4).
  EXPECT_EQ(b[2].low_us, 21);
  EXPECT_EQ(b[2].high_us, 22);
  EXPECT_EQ(b[3].low_us, 22);
  EXPECT_EQ(b[3].high_us, 24);
  // Buckets are contiguous.
  for (int i = 1; i < kNumDisplayBuckets; ++i) {
    EXPECT_EQ(b[i].low_us, b[i - 1].high_us) << i;
  }
  EXPECT_EQ(b[kOverflowBucket - 1].high_us, 20 + (1ull << 26));
  EXPECT_TRUE(std::isinf(b[kOverflowBucket].high_us));
}

TEST(DisplayBucketBoundsTest, Shift) {
  HistogramParams params;
  params.lat_min_us = 0;
  params.lat_shift = 3;
  std::vector<BucketBounds> b = DisplayBucketBounds(params);
  EXPECT_EQ(b[1].low_us, 0);
  EXPECT_EQ(b[1].high_us, 8);
  EXPECT_EQ(b[2].low_us, 8);
  EXPECT_EQ(b[2].high_us, 16);
}

TEST(ToDisplayHistTest, ReordersAndComputesOverflow) {
  CumulativeHist h;
  h.slots[LATENCY_MAX_SLOTS] = 3;  // Below min.
  h.slots[0] = 5;
  h.slots[4] = 7;
  h.total_count = 3 + 5 + 7 + 2;  // 2 above the largest bucket.
  DisplayHist d = ToDisplayHist(h, LATENCY_MAX_SLOTS);
  EXPECT_EQ(d[0], 3);
  EXPECT_EQ(d[1], 5);
  EXPECT_EQ(d[5], 7);
  EXPECT_EQ(d[kOverflowBucket], 2);
}

TEST(ToDisplayHistTest, OverflowNeverNegative) {
  CumulativeHist h;
  h.slots[0] = 5;
  h.total_count = 4;  // Racy read: count behind the slots.
  EXPECT_EQ(ToDisplayHist(h, LATENCY_MAX_SLOTS)[kOverflowBucket], 0);
}

TEST(HistPercentileTest, EmptyIsNaN) {
  DisplayHist h{};
  EXPECT_TRUE(std::isnan(
      HistPercentile(h, DisplayBucketBounds(HistogramParams()), 0.5)));
}

TEST(HistPercentileTest, InterpolatesWithinBucket) {
  const auto bounds = DisplayBucketBounds(HistogramParams());
  DisplayHist h{};
  h[3] = 100;  // [22, 24)
  EXPECT_DOUBLE_EQ(HistPercentile(h, bounds, 0.5), 23);
  EXPECT_DOUBLE_EQ(HistPercentile(h, bounds, 0.0), 22);
  EXPECT_DOUBLE_EQ(HistPercentile(h, bounds, 1.0), 24);
}

TEST(HistPercentileTest, TailPercentiles) {
  const auto bounds = DisplayBucketBounds(HistogramParams());
  DisplayHist h{};
  h[3] = 990;  // [22, 24)
  h[10] = 10;  // [20 + 2^8, 20 + 2^9) = [276, 532)
  EXPECT_DOUBLE_EQ(HistPercentile(h, bounds, 0.5), 22 + 2 * 500.0 / 990);
  EXPECT_DOUBLE_EQ(HistPercentile(h, bounds, 0.995), 276 + 0.5 * 256);
}

TEST(HistPercentileTest, OverflowReportsLowerBound) {
  const auto bounds = DisplayBucketBounds(HistogramParams());
  DisplayHist h{};
  h[kOverflowBucket] = 1;
  EXPECT_DOUBLE_EQ(HistPercentile(h, bounds, 0.5),
                   bounds[kOverflowBucket].low_us);
}

TEST(ChooseStepTest, PicksNiceSteps) {
  EXPECT_EQ(ChooseStep(absl::Minutes(5), 600, absl::Seconds(1)),
            absl::Seconds(1));
  EXPECT_EQ(ChooseStep(absl::Hours(1), 600, absl::Seconds(1)),
            absl::Seconds(10));
  EXPECT_EQ(ChooseStep(absl::Minutes(1), 600, absl::Milliseconds(250)),
            absl::Milliseconds(250));
  EXPECT_EQ(ChooseStep(absl::Minutes(15), 300, absl::Seconds(1)),
            absl::Seconds(5));
}

// Builds a snapshot where key has `count` requests, all in display bucket 3
// ([22, 24) us), each 23us.
Snapshot MakeSnapshot(absl::Time t, const HistKey& key, uint64_t count) {
  CumulativeHist h;
  h.slots[2] = count;  // BPF slot 2 == display bucket 3.
  h.total_count = count;
  h.total_sum_us = 23 * count;
  Snapshot s;
  s.time = t;
  s.hists = {{key, h}};
  return s;
}

TEST(LatencyStoreTest, EmptyStore) {
  LatencyStore store(HistogramParams(), absl::Hours(1), kStart);
  Report r = store.Query(QueryOptions(), kStart + absl::Seconds(10));
  EXPECT_EQ(r.num_snapshots, 0);
  EXPECT_EQ(r.last_sample_ms, 0);
  EXPECT_TRUE(r.series.empty());
  EXPECT_FALSE(r.t_ms.empty());
}

TEST(LatencyStoreTest, RatesAndPercentiles) {
  LatencyStore store(HistogramParams(), absl::Hours(1), kStart);
  const HistKey key{1, 2, 0};
  for (int i = 1; i <= 10; ++i) {
    store.Add(MakeSnapshot(kStart + absl::Seconds(i), key, 100 * i));
  }
  QueryOptions options;
  options.window = absl::Seconds(60);
  options.recent = absl::Seconds(5);
  Report r = store.Query(options, kStart + absl::Seconds(10));
  EXPECT_EQ(r.num_snapshots, 10);
  EXPECT_EQ(r.step_ms, 1000);
  ASSERT_THAT(r.series, SizeIs(1));
  const SeriesReport& s = r.series[0];
  EXPECT_EQ(s.key, key);

  EXPECT_EQ(s.window.count, 1000);
  EXPECT_THAT(s.window.iops, DoubleNear(100, 1e-9));
  EXPECT_THAT(s.window.avg_us, DoubleNear(23, 1e-9));
  EXPECT_THAT(s.window.p50_us, DoubleNear(23, 1e-9));
  EXPECT_EQ(s.recent.count, 500);
  EXPECT_THAT(s.recent.iops, DoubleNear(100, 1e-9));
  EXPECT_EQ(s.lifetime.count, 1000);
  EXPECT_EQ(s.window_hist[3], 1000);

  // Exactly 10 points have data, each with 100 IOPS.
  int with_data = 0;
  for (size_t i = 0; i < r.t_ms.size(); ++i) {
    if (std::isnan(s.iops[i])) continue;
    ++with_data;
    EXPECT_THAT(s.iops[i], DoubleNear(100, 1e-9));
    EXPECT_THAT(s.p99_us[i], DoubleNear(23.98, 1e-9));
  }
  EXPECT_EQ(with_data, 10);
  ASSERT_THAT(s.p50_us, SizeIs(r.t_ms.size()));
}

TEST(LatencyStoreTest, MergesSamplesIntoLargerSteps) {
  LatencyStore store(HistogramParams(), absl::Hours(1), kStart);
  const HistKey key{0, 1, 0};
  for (int i = 1; i <= 100; ++i) {
    store.Add(MakeSnapshot(kStart + absl::Seconds(i), key, 50 * i));
  }
  QueryOptions options;
  options.window = absl::Minutes(10);
  options.max_points = 60;  // -> 10s steps.
  Report r = store.Query(options, kStart + absl::Seconds(100));
  EXPECT_EQ(r.step_ms, 10000);
  ASSERT_THAT(r.series, SizeIs(1));
  for (size_t i = 0; i < r.t_ms.size(); ++i) {
    if (std::isnan(r.series[0].iops[i])) continue;
    EXPECT_THAT(r.series[0].iops[i], DoubleNear(50, 1e-9)) << i;
  }
}

TEST(LatencyStoreTest, IdleIntervalsHaveZeroRateAndNoPercentiles) {
  LatencyStore store(HistogramParams(), absl::Hours(1), kStart);
  const HistKey key{0, 2, 0};
  store.Add(MakeSnapshot(kStart + absl::Seconds(1), key, 10));
  store.Add(MakeSnapshot(kStart + absl::Seconds(2), key, 10));
  QueryOptions options;
  options.window = absl::Seconds(10);
  options.recent = absl::Seconds(1);
  Report r = store.Query(options, kStart + absl::Seconds(2));
  ASSERT_THAT(r.series, SizeIs(1));
  EXPECT_EQ(r.series[0].recent.iops, 0);
  EXPECT_TRUE(std::isnan(r.series[0].recent.p50_us));
}

TEST(LatencyStoreTest, HandlesSourceReset) {
  LatencyStore store(HistogramParams(), absl::Hours(1), kStart);
  const HistKey key{0, 2, 0};
  store.Add(MakeSnapshot(kStart + absl::Seconds(1), key, 1000));
  // The counters restarted from zero.
  store.Add(MakeSnapshot(kStart + absl::Seconds(2), key, 30));
  QueryOptions options;
  options.window = absl::Seconds(10);
  options.recent = absl::Seconds(1);
  Report r = store.Query(options, kStart + absl::Seconds(2));
  ASSERT_THAT(r.series, SizeIs(1));
  EXPECT_EQ(r.series[0].recent.count, 30);
}

TEST(LatencyStoreTest, DropsOldHistoryAndIgnoresStaleSnapshots) {
  LatencyStore store(HistogramParams(), absl::Seconds(60), kStart);
  const HistKey key{0, 2, 0};
  for (int i = 1; i <= 120; ++i) {
    store.Add(MakeSnapshot(kStart + absl::Seconds(i), key, 10 * i));
  }
  // Older than the last snapshot: ignored.
  store.Add(MakeSnapshot(kStart + absl::Seconds(5), key, 999999));
  QueryOptions options;
  options.window = absl::Seconds(120);
  Report r = store.Query(options, kStart + absl::Seconds(120));
  ASSERT_THAT(r.series, SizeIs(1));
  EXPECT_EQ(r.num_snapshots, 120);
  EXPECT_EQ(r.series[0].window.count, 600);  // Only 60s of history.
  EXPECT_EQ(r.series[0].lifetime.count, 1200);
}

TEST(LatencyStoreTest, BaselineFirstSnapshot) {
  // The source has been counting for an hour before the store attached.
  const absl::Time source_start = kStart - absl::Hours(1);
  LatencyStore store(HistogramParams(), absl::Hours(1), source_start,
                     /*baseline_first_snapshot=*/true);
  const HistKey key{0, 2, 0};
  store.Add(MakeSnapshot(kStart, key, 360000));
  store.Add(MakeSnapshot(kStart + absl::Seconds(1), key, 360100));
  store.Add(MakeSnapshot(kStart + absl::Seconds(2), key, 360200));
  QueryOptions options;
  options.window = absl::Minutes(5);
  Report r = store.Query(options, kStart + absl::Seconds(2));
  ASSERT_THAT(r.series, SizeIs(1));
  const SeriesReport& s = r.series[0];
  // Only the deltas after the first snapshot are in the window.
  EXPECT_EQ(s.window.count, 200);
  EXPECT_THAT(s.window.iops, DoubleNear(100, 1e-9));
  // The lifetime covers the whole life of the source.
  EXPECT_EQ(s.lifetime.count, 360200);
  EXPECT_THAT(s.lifetime.iops, DoubleNear(360200.0 / 3602, 1e-6));
}

TEST(LatencyStoreTest, SeriesSortedByKey) {
  LatencyStore store(HistogramParams(), absl::Hours(1), kStart);
  Snapshot s = MakeSnapshot(kStart + absl::Seconds(1), {1, 2, 0}, 5);
  s.hists.push_back(MakeSnapshot(s.time, {0, 1, 0}, 5).hists[0]);
  s.hists.push_back(MakeSnapshot(s.time, {0, 2, 0}, 5).hists[0]);
  store.Add(s);
  Report r = store.Query(QueryOptions(), kStart + absl::Seconds(1));
  ASSERT_THAT(r.series, SizeIs(3));
  EXPECT_EQ(r.series[0].key, (HistKey{0, 1, 0}));
  EXPECT_EQ(r.series[1].key, (HistKey{0, 2, 0}));
  EXPECT_EQ(r.series[2].key, (HistKey{1, 2, 0}));
}

}  // namespace
}  // namespace nvme_bpf
