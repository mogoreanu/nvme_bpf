#ifndef HISTOGRAM_H_
#define HISTOGRAM_H_

#include <cstdint>

#include "absl/status/status.h"
#include "histogram.bpf.h"
#include "types.bpf.h"

namespace nvme_bpf {

struct Histogram {
  int lat_min_us = 0;
  int lat_shift = 0;
  int max_slots = 0;

  const u64* slots = nullptr;
  uint64_t total_count = 0;
  uint64_t total_sum = 0;

  auto bucket_low(int slot) const {
    return bpf_bucket_low(slot, lat_min_us, lat_shift, max_slots);
  }
  auto bucket_high(int slot) const {
    return bpf_bucket_high(slot, lat_min_us, lat_shift, max_slots);
  }
};

absl::Status PrintHistogram(const Histogram& hist);

}  // namespace nvme_bpf

#endif /* HISTOGRAM_H_ */