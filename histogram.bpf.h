#ifndef HISTOGRAM_BPF_H
#define HISTOGRAM_BPF_H

#include "bits.bpf.h"
#include "types.bpf.h"

static inline int bpf_get_bucket(u64 v, u64 min, int shift, int max_slots) {
  if (v < min) {
    return max_slots;
  }
  v -= min;
  v >>= shift;
  if (v == 0) {
    return 0;
  }
  int s = 64 - bpf_clzll(v);
  if (s >= max_slots) {
    return -1;
  }
  return s;
}

static inline u64 bpf_bucket_high(int slot, u64 min, int shift, int max_slots) {
  if (slot == max_slots) {
    return min;
  }
  if (slot == 0) {
    return min + ((u64)1 << shift);
  }
  return min + ((u64)1 << (slot + shift));
}

static inline u64 bpf_bucket_low(int slot, u64 min, int shift, int max_slots) {
  if (slot == max_slots) {
    return 0;
  }
  if (slot == 0) {
    return min;
  }
  return bpf_bucket_high(slot - 1, min, shift, max_slots);
}

#endif /* HISTOGRAM_BPF_H */