#include "nvme_latency/latency_json.h"

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "nvme_abi.h"
#include "nvme_strings.h"

namespace nvme_bpf {

JsonWriter& JsonWriter::BeginObject() {
  BeforeValue();
  out_ += '{';
  has_items_.push_back(false);
  return *this;
}

JsonWriter& JsonWriter::EndObject() {
  out_ += '}';
  has_items_.pop_back();
  return *this;
}

JsonWriter& JsonWriter::BeginArray() {
  BeforeValue();
  out_ += '[';
  has_items_.push_back(false);
  return *this;
}

JsonWriter& JsonWriter::EndArray() {
  out_ += ']';
  has_items_.pop_back();
  return *this;
}

JsonWriter& JsonWriter::Key(absl::string_view key) {
  if (!has_items_.empty()) {
    if (has_items_.back()) out_ += ',';
    has_items_.back() = true;
  }
  AppendQuoted(key);
  out_ += ':';
  after_key_ = true;
  return *this;
}

JsonWriter& JsonWriter::String(absl::string_view value) {
  BeforeValue();
  AppendQuoted(value);
  return *this;
}

JsonWriter& JsonWriter::Int(int64_t value) {
  BeforeValue();
  absl::StrAppend(&out_, value);
  return *this;
}

JsonWriter& JsonWriter::Uint(uint64_t value) {
  BeforeValue();
  absl::StrAppend(&out_, value);
  return *this;
}

JsonWriter& JsonWriter::Double(double value) {
  BeforeValue();
  if (!std::isfinite(value)) {
    out_ += "null";
  } else if (value == std::floor(value) && std::fabs(value) < 1e15) {
    absl::StrAppend(&out_, static_cast<int64_t>(value));
  } else {
    absl::StrAppendFormat(&out_, "%.6g", value);
  }
  return *this;
}

JsonWriter& JsonWriter::Bool(bool value) {
  BeforeValue();
  out_ += value ? "true" : "false";
  return *this;
}

JsonWriter& JsonWriter::Null() {
  BeforeValue();
  out_ += "null";
  return *this;
}

void JsonWriter::BeforeValue() {
  if (after_key_) {
    after_key_ = false;
    return;
  }
  if (!has_items_.empty()) {
    if (has_items_.back()) out_ += ',';
    has_items_.back() = true;
  }
}

void JsonWriter::AppendQuoted(absl::string_view s) {
  out_ += '"';
  for (const char c : s) {
    switch (c) {
      case '"':
        out_ += "\\\"";
        break;
      case '\\':
        out_ += "\\\\";
        break;
      case '\n':
        out_ += "\\n";
        break;
      case '\r':
        out_ += "\\r";
        break;
      case '\t':
        out_ += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          absl::StrAppendFormat(&out_, "\\u%04x", static_cast<int>(c));
        } else {
          out_ += c;
        }
    }
  }
  out_ += '"';
}

std::string OpcodeName(uint8_t opcode) {
  const absl::string_view name =
      nvme_abi::NvmeIoOpcodeToString(static_cast<nvme_abi::NvmeOpcode>(opcode));
  if (name == "UnknownIoOp") return absl::StrFormat("Op 0x%02x", opcode);
  return std::string(name);
}

std::string SizeClassName(uint8_t opcode, uint8_t size_class,
                          bool split_size) {
  // Flush transfers no data, its size class is meaningless.
  if (!split_size ||
      opcode == static_cast<uint8_t>(nvme_abi::NvmeOpcode::kFlush)) {
    return "all sizes";
  }
  switch (size_class) {
    case 0:
      return "\u2264 16 KiB";
    case 1:
      return "16\u201364 KiB";
    default:
      return "> 64 KiB";
  }
}

std::string SeriesId(const HistKey& key) {
  return absl::StrCat("c", key.ctrl_id, "-o", key.opcode, "-s",
                      key.size_class);
}

namespace {

void WriteDoubles(JsonWriter& w, absl::string_view key,
                  const std::vector<double>& values) {
  w.Key(key).BeginArray();
  for (double v : values) w.Double(v);
  w.EndArray();
}

void WriteHist(JsonWriter& w, absl::string_view key, const DisplayHist& hist) {
  w.Key(key).BeginArray();
  for (uint64_t v : hist) w.Uint(v);
  w.EndArray();
}

void WriteStats(JsonWriter& w, absl::string_view key, const LatencyStats& s) {
  w.Key(key).BeginObject();
  w.Key("count").Uint(s.count);
  w.Key("overflow").Uint(s.overflow);
  w.Key("duration_s").Double(s.duration_s);
  w.Key("iops").Double(s.iops);
  w.Key("avg_us").Double(s.avg_us);
  w.Key("p50_us").Double(s.p50_us);
  w.Key("p90_us").Double(s.p90_us);
  w.Key("p99_us").Double(s.p99_us);
  w.Key("p999_us").Double(s.p999_us);
  w.EndObject();
}

}  // namespace

std::string ConfigId(const DashboardConfig& config) {
  return absl::StrCat(config.source_name, "-", config.start_ms, "-",
                      config.params.lat_min_us, "-", config.params.lat_shift,
                      "-", config.split_size, "-", config.ctrl_id_filter, "-",
                      config.nsid_filter, "-", config.sample_interval_ms);
}

std::string ConfigToJson(const DashboardConfig& config,
                         const std::vector<BucketBounds>& bounds) {
  JsonWriter w;
  w.BeginObject();
  w.Key("config_id").String(ConfigId(config));
  w.Key("source").String(config.source_name);
  w.Key("hostname").String(config.hostname);
  w.Key("sample_interval_ms").Int(config.sample_interval_ms);
  w.Key("history_s").Int(config.history_s);
  w.Key("start_ms").Int(config.start_ms);
  w.Key("split_size").Bool(config.split_size);
  w.Key("ctrl_id_filter").Int(config.ctrl_id_filter);
  w.Key("nsid_filter").Int(config.nsid_filter);
  w.Key("lat_min_us").Uint(config.params.lat_min_us);
  w.Key("lat_shift").Int(config.params.lat_shift);
  w.Key("max_slots").Int(config.params.max_slots);
  w.Key("buckets").BeginArray();
  for (const BucketBounds& b : bounds) {
    w.BeginArray().Double(b.low_us).Double(b.high_us).EndArray();
  }
  w.EndArray();
  w.EndObject();
  return w.str();
}

std::string ReportToJson(const Report& report, const SourceStatus& status,
                         const DashboardConfig& config) {
  const bool split_size = config.split_size;
  JsonWriter w;
  w.BeginObject();
  w.Key("config_id").String(ConfigId(config));
  w.Key("now_ms").Int(report.now_ms);
  w.Key("window_ms").Int(report.window_ms);
  w.Key("step_ms").Int(report.step_ms);
  w.Key("start_ms").Int(report.start_ms);
  w.Key("last_sample_ms").Int(report.last_sample_ms);
  w.Key("num_snapshots").Int(report.num_snapshots);

  w.Key("status").BeginObject();
  w.Key("source").String(status.name);
  w.Key("healthy").Bool(status.healthy);
  w.Key("last_error").String(status.last_error);
  w.Key("read_errors").Int(status.read_errors);
  w.EndObject();

  w.Key("t").BeginArray();
  for (int64_t t : report.t_ms) w.Int(t);
  w.EndArray();

  w.Key("series").BeginArray();
  for (const SeriesReport& s : report.series) {
    w.BeginObject();
    w.Key("id").String(SeriesId(s.key));
    w.Key("ctrl_id").Uint(s.key.ctrl_id);
    w.Key("opcode").Uint(s.key.opcode);
    w.Key("size_class").Uint(s.key.size_class);
    w.Key("opcode_name").String(OpcodeName(s.key.opcode));
    w.Key("size_class_name")
        .String(SizeClassName(s.key.opcode, s.key.size_class, split_size));
    WriteDoubles(w, "p50", s.p50_us);
    WriteDoubles(w, "p90", s.p90_us);
    WriteDoubles(w, "p99", s.p99_us);
    WriteDoubles(w, "p999", s.p999_us);
    WriteDoubles(w, "avg", s.avg_us);
    WriteDoubles(w, "iops", s.iops);
    WriteStats(w, "recent", s.recent);
    WriteStats(w, "window", s.window);
    WriteStats(w, "lifetime", s.lifetime);
    WriteHist(w, "window_hist", s.window_hist);
    WriteHist(w, "lifetime_hist", s.lifetime_hist);
    w.EndObject();
  }
  w.EndArray();
  w.EndObject();
  return w.str();
}

}  // namespace nvme_bpf
