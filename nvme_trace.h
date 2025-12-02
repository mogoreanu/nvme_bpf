#ifndef __NVME_TRACE_H_
#define __NVME_TRACE_H_

#include "types.bpf.h"

enum ActionType {
  kActionTypeUnknown = 0,
  kActionTypeSubmit = 1,
  kActionTypeComplete = 2,
};

struct nvme_submit_trace_event {
  enum ActionType action;
  // Timestamp in nanoseconds
  u64 ts_ns;
  char disk[32];
  int ctrl_id;
  int qid;
  u8 opcode;
  u8 flags;
  u8 fctype;
  u16 cid;
  u32 nsid;
  bool metadata;
  u8 cdw10[24];
};
struct nvme_complete_trace_event {
  enum ActionType action;
  // Timestamp in nanoseconds
  u64 ts_ns;
  char disk[32];
  int ctrl_id;
  int qid;
  int cid;
  u64 result;
  u8 retries;
  u8 flags;
  u16 status;
};

struct nvme_trace_event {
  enum ActionType action;
};

#endif  // __NVME_TRACE_H_
