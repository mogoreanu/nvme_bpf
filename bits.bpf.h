#ifndef __BITS_BPF_H
#define __BITS_BPF_H

#include "types.bpf.h"

// Maybe there's a way to optimize this inefficient clz
// https://stackoverflow.com/questions/70308156/how-to-efficiently-count-leading-zeros-in-a-24-bit-unsigned-integer
inline int bpf_clzll(u64 x) {
  // __builtin_clzll causes a segfault in clang
  int zeroes = 63;
  if (x >> 32) {
    zeroes -= 32;
    x >>= 32;
  }
  if (x >> 16) {
    zeroes -= 16;
    x >>= 16;
  }
  if (x >> 8) {
    zeroes -= 8;
    x >>= 8;
  }
  if (x >> 4) {
    zeroes -= 4;
    x >>= 4;
  }
  if (x >> 2) {
    zeroes -= 2;
    x >>= 2;
  }
  if (x >> 1) {
    zeroes -= 1;
    x >>= 1;
  }
  if (x != 0) {
    return zeroes;
  } else {
    return zeroes + 1;
  }
}

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

static inline u64 bpf_log_bucket_low(u64 value) {
  if (value == 0) {
    return 0;
  }
  return (u64)1 << value;
}

static inline u64 bpf_log_bucket_high(u64 value) {
  if (value == 0) {
    return 1;
  }
  return ((u64)1 << (value + 1)) - 1;
}

#endif /* __BITS_BPF_H */
