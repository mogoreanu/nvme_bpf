#include <cstdint>
#include <limits>
#include <string>

#include "absl/time/time.h"
#include "nvme_latency/fake_latency_source.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nvme_latency/latency_json.h"
#include "nvme_latency/latency_source.h"
#include "nvme_latency/latency_store.h"

namespace nvme_bpf {
namespace {

using ::testing::HasSubstr;
using ::testing::Not;

TEST(JsonWriterTest, WritesNestedValues) {
  JsonWriter w;
  w.BeginObject();
  w.Key("a").Int(1);
  w.Key("b").BeginArray();
  w.Double(1.5).Double(std::numeric_limits<double>::quiet_NaN());
  w.String("x\"y\\z\n").Bool(false).Null();
  w.BeginObject().EndObject();
  w.EndArray();
  w.Key("c").Uint(18446744073709551615ull);
  w.Key("d").Double(42.0);
  w.EndObject();
  EXPECT_EQ(w.str(),
            R"({"a":1,"b":[1.5,null,"x\"y\\z\n",false,null,{}],)"
            R"("c":18446744073709551615,"d":42})");
}

TEST(NamesTest, OpcodesAndSizes) {
  EXPECT_EQ(OpcodeName(2), "Read");
  EXPECT_EQ(OpcodeName(1), "Write");
  EXPECT_EQ(OpcodeName(0), "Flush");
  EXPECT_EQ(OpcodeName(0x99), "Op 0x99");
  EXPECT_EQ(SizeClassName(2, 0, false), "all sizes");
  EXPECT_EQ(SizeClassName(2, 2, true), "> 64 KiB");
  EXPECT_EQ(SizeClassName(0, 0, true), "all sizes");  // Flush.
  EXPECT_EQ(SeriesId({3, 2, 1}), "c3-o2-s1");
}

// A clock advanced manually by the tests.
absl::Time g_fake_now = absl::FromUnixSeconds(1'700'000'000);
absl::Time FakeNow() { return g_fake_now; }

TEST(FakeSourceTest, GeneratesTrafficAndFeedsTheStore) {
  FakeSourceOptions options;
  options.now = &FakeNow;
  options.seed = 42;
  std::unique_ptr<LatencySource> source = CreateFakeLatencySource(options);
  EXPECT_EQ(source->name(), "fake");

  const absl::Time start = g_fake_now;
  LatencyStore store(options.params, absl::Hours(1), start);
  for (int i = 0; i < 5; ++i) {
    g_fake_now += absl::Seconds(1);
    absl::StatusOr<Snapshot> snapshot = source->Read();
    ASSERT_TRUE(snapshot.ok());
    store.Add(*snapshot);
  }
  QueryOptions query;
  query.window = absl::Minutes(1);
  Report report = store.Query(query, g_fake_now);
  // Two controllers: Read/Write/Flush on nvme0, Read/Write on nvme1.
  ASSERT_EQ(report.series.size(), 5u);
  for (const SeriesReport& s : report.series) {
    EXPECT_GT(s.window.count, 0u) << SeriesId(s.key);
    EXPECT_GT(s.window.p50_us, 0) << SeriesId(s.key);
    EXPECT_LE(s.window.p50_us, s.window.p99_us) << SeriesId(s.key);
    EXPECT_LE(s.window.p99_us, s.window.p999_us) << SeriesId(s.key);
  }

  const std::string json =
      ReportToJson(report, SourceStatus{"fake"}, DashboardConfig());
  EXPECT_THAT(json, HasSubstr(R"("id":"c0-o2-s0")"));
  EXPECT_THAT(json, HasSubstr(R"("opcode_name":"Read")"));
  EXPECT_THAT(json, Not(HasSubstr("nan")));
  EXPECT_THAT(json, Not(HasSubstr("inf")));
}

TEST(FakeSourceTest, SplitSizeAndControllerFilter) {
  FakeSourceOptions options;
  options.now = &FakeNow;
  options.split_size = true;
  options.ctrl_id_filter = 1;
  std::unique_ptr<LatencySource> source = CreateFakeLatencySource(options);
  g_fake_now += absl::Seconds(2);
  absl::StatusOr<Snapshot> snapshot = source->Read();
  ASSERT_TRUE(snapshot.ok());
  // nvme1: Read and Write, 3 size classes each.
  ASSERT_EQ(snapshot->hists.size(), 6u);
  for (const auto& [key, hist] : snapshot->hists) {
    EXPECT_EQ(key.ctrl_id, 1u);
    EXPECT_GT(hist.total_count, 0u);
  }
}

TEST(ConfigToJsonTest, IncludesBuckets) {
  DashboardConfig config;
  config.source_name = "fake";
  const std::string json =
      ConfigToJson(config, DisplayBucketBounds(config.params));
  EXPECT_THAT(json, HasSubstr(R"("buckets":[[0,20],[20,21],[21,22],[22,24],)"));
  // The overflow bucket has no upper bound.
  EXPECT_THAT(json, HasSubstr(",null]]"));
}

}  // namespace
}  // namespace nvme_bpf
