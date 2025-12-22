#include "histogram.h"

#include "absl/strings/str_join.h"

namespace nvme_bpf {

absl::Status PrintHistogram(const Histogram& hist) {
  int first_nonzero_slot = 0;
  while (first_nonzero_slot < hist.max_slots &&
         hist.slots[first_nonzero_slot] == 0) {
    ++first_nonzero_slot;
  }
  if (first_nonzero_slot == hist.max_slots) {
    std::cout << "  (all zero slots)" << std::endl;
    return absl::OkStatus();
  }
  int last_nonzero_slot = hist.max_slots - 1;
  while (last_nonzero_slot >= first_nonzero_slot &&
         hist.slots[last_nonzero_slot] == 0) {
    --last_nonzero_slot;
  }

  uint64_t computed_total_count = hist.slots[hist.max_slots];

  for (int slot = first_nonzero_slot; slot <= last_nonzero_slot; ++slot) {
    computed_total_count += hist.slots[slot];
  }

  if (computed_total_count != hist.total_count) {
    std::cerr << "Warning: total_count mismatch: computed="
              << computed_total_count << ", recorded=" << hist.total_count
              << std::endl;
  }

  std::vector<std::vector<std::string>> rows;
  rows.push_back({"Latency Range", "Count", "Cumulative Percent"});

  uint64_t accumulated_total_count = 0;
  if (hist.slots[hist.max_slots] != 0) {
    accumulated_total_count += hist.slots[hist.max_slots];
    rows.push_back(
        {absl::StrCat("  [", hist.bucket_low(hist.max_slots), "us - ",
                      hist.bucket_high(hist.max_slots), "us):"),
         absl::StrCat(hist.slots[hist.max_slots]),
         absl::StrCat(100.0 * accumulated_total_count / computed_total_count)});
  }

  for (int slot = first_nonzero_slot; slot <= last_nonzero_slot; ++slot) {
    accumulated_total_count += hist.slots[slot];
    rows.push_back(
        {absl::StrCat("  [", hist.bucket_low(slot), "us - ",
                      hist.bucket_high(slot), "us):"),
         absl::StrCat(hist.slots[slot]),
         absl::StrCat(100.0 * accumulated_total_count / computed_total_count)});
  }

  using TColWidth = decltype(rows[0][0].size());
  std::vector<TColWidth> max_col_width;
  for (const auto& row : rows) {
    if (max_col_width.size() < row.size()) {
      max_col_width.resize(row.size(), 0);
    }
    for (TColWidth col = 0; col < row.size(); ++col) {
      if (row[col].size() > max_col_width[col]) {
        max_col_width[col] = row[col].size();
      }
    }
  }
  for (const auto& row : rows) {
    for (TColWidth col = 0; col < row.size(); ++col) {
      std::cout << std::left << std::setw(max_col_width[col] + 2) << row[col];
    }
    std::cout << std::endl;
  }
  std::cout << "  Total count: " << hist.total_count
            << " avg=" << static_cast<double>(hist.total_sum) / hist.total_count
            << std::endl;
  return absl::OkStatus();
}

}  // namespace nvme_bpf
