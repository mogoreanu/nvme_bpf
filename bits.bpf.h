#ifndef __BITS_BPF_H
#define __BITS_BPF_H

#include "types.bpf.h"

static inline u64 bpf_log2(u32 v) {
  u32 shift, r;

  r = (v > 0xFFFF) << 4;
  v >>= r;

  shift = (v > 0xFF) << 3;
  v >>= shift;
  r |= shift;

  shift = (v > 0xF) << 2;
  v >>= shift;
  r |= shift;

  shift = (v > 0x3) << 1;
  v >>= shift;
  r |= shift;

  r |= (v >> 1);

  return r;
}

static inline u64 bpf_log2l(u64 v) {
  u32 hi = v >> 32;

  if (hi)
    return bpf_log2(hi) + 32;
  else
    return bpf_log2(v);
}

static inline u64 bpf_bucket_low(u64 value) {
  if (value == 0) {
    return 0;
  }
  return (u64)1 << value;
}

static inline u64 bpf_bucket_high(u64 value) {
  if (value == 0) {
    return 1;
  }
  return ((u64)1 << (value + 1)) - 1;
}

#endif /* __BITS_BPF_H */
