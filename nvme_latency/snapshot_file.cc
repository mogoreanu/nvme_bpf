#include "nvme_latency/snapshot_file.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "nvme_latency/latency_source.h"

namespace nvme_bpf {
namespace {

constexpr absl::string_view kMagic = "nvme_latency_snapshot";
constexpr int kVersion = 1;
constexpr size_t kMaxFileBytes = 4 << 20;

std::string Dirname(const std::string& path) {
  const size_t slash = path.find_last_of('/');
  if (slash == std::string::npos) return ".";
  if (slash == 0) return "/";
  return path.substr(0, slash);
}

template <typename T>
bool ParseInt(absl::string_view s, T* out) {
  int64_t v;
  if (!absl::SimpleAtoi(s, &v)) return false;
  *out = static_cast<T>(v);
  return true;
}

absl::Status ParseError(int line, absl::string_view message) {
  return absl::DataLossError(
      absl::StrCat("Malformed snapshot at line ", line, ": ", message));
}

}  // namespace

std::string SerializeSnapshot(const Snapshot& s) {
  const SourceInfo& info = s.info;
  std::string out = absl::StrCat(
      kMagic, " ", kVersion, "\n",
      "source ", info.source.empty() ? "unknown" : info.source, "\n",
      "time_us ", absl::ToUnixMicros(s.time), "\n",
      "start_us ", absl::ToUnixMicros(info.start_time), "\n",
      "interval_us ", absl::ToInt64Microseconds(info.interval), "\n",
      "lat_min_us ", info.params.lat_min_us, "\n",
      "lat_shift ", info.params.lat_shift, "\n",
      "max_slots ", info.params.max_slots, "\n",
      "split_size ", info.split_size ? 1 : 0, "\n",
      "ctrl_id_filter ", info.ctrl_id_filter, "\n",
      "nsid_filter ", info.nsid_filter, "\n");
  for (const auto& [key, hist] : s.hists) {
    absl::StrAppend(&out, "hist ", key.ctrl_id, " ", key.opcode, " ",
                    key.size_class, " ", hist.total_count, " ",
                    hist.total_sum_us);
    for (uint64_t slot : hist.slots) absl::StrAppend(&out, " ", slot);
    out += "\n";
  }
  out += "end\n";
  return out;
}

absl::StatusOr<Snapshot> ParseSnapshot(absl::string_view text) {
  Snapshot s;
  bool header = false;
  bool end = false;
  int line_no = 0;
  for (absl::string_view line : absl::StrSplit(text, '\n')) {
    ++line_no;
    if (line.empty()) continue;
    if (end) return ParseError(line_no, "data after 'end'");
    const std::vector<absl::string_view> f =
        absl::StrSplit(line, ' ', absl::SkipEmpty());
    if (f.empty()) continue;
    if (!header) {
      int version = 0;
      if (f.size() != 2 || f[0] != kMagic || !ParseInt(f[1], &version)) {
        return ParseError(line_no, "not an nvme_latency snapshot");
      }
      if (version != kVersion) {
        return ParseError(line_no, absl::StrCat("unsupported version ",
                                                version));
      }
      header = true;
      continue;
    }
    const absl::string_view key = f[0];
    if (key == "end") {
      end = true;
      continue;
    }
    if (key == "hist") {
      const int max_slots = s.info.params.max_slots;
      if (max_slots != LATENCY_MAX_SLOTS) {
        return ParseError(line_no, absl::StrCat("expected max_slots ",
                                                LATENCY_MAX_SLOTS));
      }
      if (f.size() != static_cast<size_t>(6 + max_slots + 1)) {
        return ParseError(line_no, "wrong number of hist fields");
      }
      HistKey hk;
      CumulativeHist h;
      bool ok = ParseInt(f[1], &hk.ctrl_id) && ParseInt(f[2], &hk.opcode) &&
                ParseInt(f[3], &hk.size_class) &&
                absl::SimpleAtoi(f[4], &h.total_count) &&
                absl::SimpleAtoi(f[5], &h.total_sum_us);
      for (int i = 0; ok && i <= max_slots; ++i) {
        ok = absl::SimpleAtoi(f[6 + i], &h.slots[i]);
      }
      if (!ok) return ParseError(line_no, "bad hist value");
      s.hists.emplace_back(hk, h);
      continue;
    }
    if (f.size() != 2) continue;  // Unknown or malformed key: ignore.
    const absl::string_view value = f[1];
    int64_t v = 0;
    if (key == "source") {
      s.info.source = std::string(value);
      continue;
    }
    if (!absl::SimpleAtoi(value, &v)) {
      return ParseError(line_no, absl::StrCat("bad value for ", key));
    }
    if (key == "time_us") {
      s.time = absl::FromUnixMicros(v);
    } else if (key == "start_us") {
      s.info.start_time = absl::FromUnixMicros(v);
    } else if (key == "interval_us") {
      s.info.interval = absl::Microseconds(v);
    } else if (key == "lat_min_us") {
      s.info.params.lat_min_us = static_cast<uint64_t>(v);
    } else if (key == "lat_shift") {
      s.info.params.lat_shift = static_cast<int>(v);
    } else if (key == "max_slots") {
      s.info.params.max_slots = static_cast<int>(v);
    } else if (key == "split_size") {
      s.info.split_size = v != 0;
    } else if (key == "ctrl_id_filter") {
      s.info.ctrl_id_filter = static_cast<int>(v);
    } else if (key == "nsid_filter") {
      s.info.nsid_filter = static_cast<int>(v);
    }
  }
  if (!header) return absl::DataLossError("Empty snapshot");
  if (!end) return absl::DataLossError("Truncated snapshot (no 'end')");
  std::sort(s.hists.begin(), s.hists.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  return s;
}

absl::Status PrepareSnapshotDir(const std::string& path) {
  const std::string dir = Dirname(path);
  struct stat st;
  if (stat(dir.c_str(), &st) != 0) {
    if (errno != ENOENT) {
      return absl::ErrnoToStatus(errno, absl::StrCat("Cannot stat ", dir));
    }
    if (mkdir(dir.c_str(), 0755) != 0) {
      return absl::ErrnoToStatus(errno, absl::StrCat("Cannot create ", dir));
    }
    chmod(dir.c_str(), 0755);  // Regardless of the umask.
    if (stat(dir.c_str(), &st) != 0) {
      return absl::ErrnoToStatus(errno, absl::StrCat("Cannot stat ", dir));
    }
  }
  if (!S_ISDIR(st.st_mode)) {
    return absl::FailedPreconditionError(
        absl::StrCat(dir, " is not a directory"));
  }
  if (geteuid() == 0) {
    const bool others_can_write = (st.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    const bool sticky = (st.st_mode & S_ISVTX) != 0;
    if (st.st_uid != 0 || (others_can_write && !sticky)) {
      return absl::FailedPreconditionError(absl::StrCat(
          "Refusing to write snapshots as root into ", dir,
          ": it is not owned by root or is writable by other users"));
    }
  }
  return absl::OkStatus();
}

absl::Status WriteSnapshotFile(const std::string& path,
                               const Snapshot& snapshot) {
  const std::string data = SerializeSnapshot(snapshot);
  std::string tmp = Dirname(path) + "/.snapshot.XXXXXX";
  // mkostemp creates the file with O_EXCL, so it never follows a symlink.
  const int fd = mkostemp(tmp.data(), O_CLOEXEC);
  if (fd < 0) {
    return absl::ErrnoToStatus(
        errno, absl::StrCat("Cannot create a temporary file for ", path));
  }
  absl::Status status = absl::OkStatus();
  if (fchmod(fd, 0644) != 0) {
    status = absl::ErrnoToStatus(errno, "fchmod");
  }
  for (absl::string_view rest = data; status.ok() && !rest.empty();) {
    const ssize_t n = write(fd, rest.data(), rest.size());
    if (n < 0) {
      if (errno == EINTR) continue;
      status = absl::ErrnoToStatus(errno, absl::StrCat("Writing ", tmp));
      break;
    }
    rest.remove_prefix(static_cast<size_t>(n));
  }
  if (close(fd) != 0 && status.ok()) {
    status = absl::ErrnoToStatus(errno, absl::StrCat("Closing ", tmp));
  }
  if (status.ok() && rename(tmp.c_str(), path.c_str()) != 0) {
    status = absl::ErrnoToStatus(errno, absl::StrCat("Renaming to ", path));
  }
  if (!status.ok()) unlink(tmp.c_str());
  return status;
}

absl::StatusOr<Snapshot> ReadSnapshotFile(const std::string& path) {
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return absl::ErrnoToStatus(errno, absl::StrCat("Cannot open ", path));
  }
  std::string data;
  char buffer[16384];
  while (true) {
    const ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n < 0) {
      if (errno == EINTR) continue;
      const int err = errno;
      close(fd);
      return absl::ErrnoToStatus(err, absl::StrCat("Cannot read ", path));
    }
    if (n == 0) break;
    data.append(buffer, static_cast<size_t>(n));
    if (data.size() > kMaxFileBytes) {
      close(fd);
      return absl::ResourceExhaustedError(
          absl::StrCat(path, " is too large for a snapshot"));
    }
  }
  close(fd);
  return ParseSnapshot(data);
}

namespace {

class SnapshotFileSource : public LatencySource {
 public:
  explicit SnapshotFileSource(SnapshotFileSourceOptions options)
      : options_(std::move(options)) {}

  std::string name() const override { return "snapshot"; }

  absl::StatusOr<Snapshot> Read() override {
    absl::StatusOr<Snapshot> snapshot = ReadSnapshotFile(options_.path);
    if (!snapshot.ok()) {
      if (absl::IsNotFound(snapshot.status())) {
        return absl::UnavailableError(absl::StrCat(
            "No snapshot at ", options_.path,
            ", is the collector running? Start it with: "
            "sudo nvme_latency --print=summary"));
      }
      return snapshot.status();
    }
    const absl::Duration age = options_.now() - snapshot->time;
    const absl::Duration limit =
        std::max(options_.max_age, 5 * snapshot->info.interval);
    if (age > limit) {
      return absl::UnavailableError(absl::StrCat(
          "The snapshot at ", options_.path, " is stale (",
          absl::FormatDuration(absl::Trunc(age, absl::Seconds(1))),
          " old), is nvme_latency still running?"));
    }
    return snapshot;
  }

 private:
  const SnapshotFileSourceOptions options_;
};

}  // namespace

std::unique_ptr<LatencySource> CreateSnapshotFileSource(
    const SnapshotFileSourceOptions& options) {
  return std::make_unique<SnapshotFileSource>(options);
}

}  // namespace nvme_bpf
