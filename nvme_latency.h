#ifndef NVME_LATENCY_H_
#define NVME_LATENCY_H_

#include "types.bpf.h"

#define LATENCY_MAX_SLOTS 27

struct request_key {
  int ctrl_id;
  int qid;
  u16 cid;
};

struct request_data {
  u64 start_ns;
  u8 opcode;
};

struct latency_hist_key {
  u32 ctrl_id;
  u8 opcode;
};

struct latency_hist {
  u64 slots[LATENCY_MAX_SLOTS + 1];
  u64 total_sum;
  u64 total_count;
};

#endif  // NVME_LATENCY_H_