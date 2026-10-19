#include "nvme_latency/snapshot_file.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {
namespace {

using ::testing::HasSubstr;

Snapshot MakeSnapshot() {
  Snapshot s;
  s.time = absl::FromUnixMicros(1792430000123456);
  s.info.source = "bpf";
  s.info.start_time = absl::FromUnixMicros(1792429000000000);
  s.info.interval = absl::Milliseconds(500);
  s.info.params.lat_min_us = 65;
  s.info.params.lat_shift = 2;
  s.info.split_size = true;
  s.info.ctrl_id_filter = 3;
  s.info.nsid_filter = 1;
  CumulativeHist a;
  a.slots[0] = 1;
  a.slots[LATENCY_MAX_SLOTS] = 7;
  a.total_count = 10;
  a.total_sum_us = 12345;
  CumulativeHist b;
  b.slots[5] = 18446744073709551615ull;
  b.total_count = 18446744073709551615ull;
  s.hists = {{HistKey{1, 2, 0}, a}, {HistKey{3, 9, 2}, b}};
  return s;
}

std::string TempDir() {
  const char* dir = std::getenv("TEST_TMPDIR");
  return dir ? dir : "/tmp";
}

TEST(SnapshotFormatTest, RoundTrip) {
  const Snapshot s = MakeSnapshot();
  const std::string text = SerializeSnapshot(s);
  EXPECT_THAT(text, HasSubstr("nvme_latency_snapshot 1\n"));
  EXPECT_THAT(text, HasSubstr("\nhist 1 2 0 10 12345 1 0 "));
  absl::StatusOr<Snapshot> parsed = ParseSnapshot(text);
  ASSERT_TRUE(parsed.ok()) << parsed.status();
  EXPECT_EQ(parsed->time, s.time);
  EXPECT_EQ(parsed->info, s.info);
  EXPECT_EQ(parsed->hists, s.hists);
}

TEST(SnapshotFormatTest, IgnoresUnknownKeys) {
  std::string text = SerializeSnapshot(MakeSnapshot());
  text = absl::StrReplaceAll(text, {{"end\n", "future_key 42\nend\n"}});
  EXPECT_TRUE(ParseSnapshot(text).ok());
}

TEST(SnapshotFormatTest, RejectsBadInput) {
  const std::string good = SerializeSnapshot(MakeSnapshot());
  EXPECT_FALSE(ParseSnapshot("").ok());
  EXPECT_FALSE(ParseSnapshot("hello world\n").ok());
  EXPECT_FALSE(ParseSnapshot("nvme_latency_snapshot 2\nend\n").ok());
  // Truncated.
  EXPECT_FALSE(ParseSnapshot(good.substr(0, good.size() - 4)).ok());
  // Bad numbers / field counts.
  EXPECT_FALSE(
      ParseSnapshot(absl::StrReplaceAll(good, {{"hist 1 2 0 10", "hist 1 x 0 10"}}))
          .ok());
  EXPECT_FALSE(
      ParseSnapshot(absl::StrReplaceAll(good, {{"hist 1 2 0 10 ", "hist 1 2 0 "}}))
          .ok());
  EXPECT_FALSE(
      ParseSnapshot(absl::StrReplaceAll(good, {{"max_slots 27", "max_slots 9"}}))
          .ok());
}

TEST(SnapshotFileTest, WriteAndRead) {
  const std::string dir = absl::StrCat(TempDir(), "/snapdir");
  const std::string path = dir + "/snapshot";
  ASSERT_TRUE(PrepareSnapshotDir(path).ok());
  struct stat st;
  ASSERT_EQ(stat(dir.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0755);

  const Snapshot s = MakeSnapshot();
  ASSERT_TRUE(WriteSnapshotFile(path, s).ok());
  ASSERT_EQ(stat(path.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0644);  // Readable by the dashboard user.

  // Overwrite.
  Snapshot s2 = s;
  s2.time += absl::Seconds(1);
  ASSERT_TRUE(WriteSnapshotFile(path, s2).ok());
  absl::StatusOr<Snapshot> read = ReadSnapshotFile(path);
  ASSERT_TRUE(read.ok()) << read.status();
  EXPECT_EQ(read->time, s2.time);
  EXPECT_EQ(read->hists, s.hists);
}

TEST(SnapshotFileTest, MissingFile) {
  EXPECT_TRUE(absl::IsNotFound(
      ReadSnapshotFile(TempDir() + "/does/not/exist").status()));
}

absl::Time g_now;
absl::Time Now() { return g_now; }

TEST(SnapshotFileSourceTest, ReportsMissingAndStaleSnapshots) {
  const std::string path = TempDir() + "/source_snapshot";
  unlink(path.c_str());
  SnapshotFileSourceOptions options;
  options.path = path;
  options.now = &Now;
  std::unique_ptr<LatencySource> source = CreateSnapshotFileSource(options);

  absl::StatusOr<Snapshot> r = source->Read();
  EXPECT_TRUE(absl::IsUnavailable(r.status()));
  EXPECT_THAT(r.status().message(), HasSubstr("is the collector running"));

  const Snapshot s = MakeSnapshot();  // 500ms interval.
  ASSERT_TRUE(WriteSnapshotFile(path, s).ok());
  g_now = s.time + absl::Seconds(2);
  r = source->Read();
  ASSERT_TRUE(r.ok()) << r.status();
  EXPECT_EQ(r->hists.size(), 2u);

  g_now = s.time + absl::Seconds(30);
  r = source->Read();
  EXPECT_TRUE(absl::IsUnavailable(r.status()));
  EXPECT_THAT(r.status().message(), HasSubstr("stale"));
}

}  // namespace
}  // namespace nvme_bpf
