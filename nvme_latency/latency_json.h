#ifndef NVME_BPF_LATENCY_JSON_H_
#define NVME_BPF_LATENCY_JSON_H_

#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "nvme_latency/latency_source.h"
#include "nvme_latency/latency_store.h"

namespace nvme_bpf {

// A minimal streaming JSON writer. Non-finite doubles are written as null.
class JsonWriter {
 public:
  JsonWriter& BeginObject();
  JsonWriter& EndObject();
  JsonWriter& BeginArray();
  JsonWriter& EndArray();
  JsonWriter& Key(absl::string_view key);
  JsonWriter& String(absl::string_view value);
  JsonWriter& Int(int64_t value);
  JsonWriter& Uint(uint64_t value);
  JsonWriter& Double(double value);
  JsonWriter& Bool(bool value);
  JsonWriter& Null();

  const std::string& str() const { return out_; }

 private:
  void BeforeValue();
  void AppendQuoted(absl::string_view s);

  std::string out_;
  std::vector<bool> has_items_;
  bool after_key_ = false;
};

// Human readable names used by the UI.
std::string OpcodeName(uint8_t opcode);
std::string SizeClassName(uint8_t opcode, uint8_t size_class, bool split_size);
// Stable identifier of a series, safe to use in URLs, e.g. "c0-o2-s0".
std::string SeriesId(const HistKey& key);

struct SourceStatus {
  std::string name;
  bool healthy = true;
  std::string last_error;
  int64_t read_errors = 0;
};

struct DashboardConfig {
  HistogramParams params;
  std::string source_name;
  std::string hostname;
  int64_t sample_interval_ms = 1000;
  int64_t history_s = 3600;
  int64_t start_ms = 0;
  bool split_size = false;
  int ctrl_id_filter = -1;
  int nsid_filter = -1;
};

// Identifies the collection settings. Changes when the collector restarts or
// its settings change, which tells the UI to reload the configuration.
std::string ConfigId(const DashboardConfig& config);

std::string ConfigToJson(const DashboardConfig& config,
                         const std::vector<BucketBounds>& bounds);

std::string ReportToJson(const Report& report, const SourceStatus& status,
                         const DashboardConfig& config);

}  // namespace nvme_bpf

#endif  // NVME_BPF_LATENCY_JSON_H_
