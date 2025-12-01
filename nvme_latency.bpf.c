// clang-format off
#include "nvme_core.h"
// clang-format on

#include "nvme_latency.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bits.bpf.h"
#include "types.bpf.h"

char LICENSE[] SEC("license") = "MIT";

#define MAX_LATENCY_ENTRIES 20
#define ALL_CTRL_ID 0xFFFFFFFF
#define ALL_OPCODE 0xFF

const volatile __u32 filter_ctrl_id = ALL_CTRL_ID;
const volatile __u8 filter_opcode = ALL_OPCODE;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct request_key);
  __type(value, struct request_data);
} in_flight SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_LATENCY_ENTRIES);
  __type(key, struct latency_hist_key);
  __type(value, struct latency_hist);
} hists SEC(".maps");

#define VLOG

SEC("tp/nvme/nvme_setup_cmd")
int handle_nvme_setup_cmd(struct trace_event_raw_nvme_setup_cmd* ctx) {
  // Requires CONFIG_TRACING and CONFIG_BPF_EVENTS
  // /sys/kernel/debug/tracing/trace_pipe`
  // bpf_printk("nvme_setup_cmd: PID %d, qid=%d, cid=%d, opcode=0x%x\n",
  //            bpf_get_current_pid_tgid() >> 32, ctx->qid, ctx->cid,
  //            ctx->opcode);
  if (filter_ctrl_id != ALL_CTRL_ID && ctx->ctrl_id != (int)filter_ctrl_id) {
    return 0;
  }
  if (filter_opcode != ALL_OPCODE && ctx->opcode != (u8)filter_opcode) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  // Important to initialize the key, outherwise garbage padding (probably) may
  // lead to lookup failures.
  struct request_key req_key = {};
  req_key.ctrl_id = ctx->ctrl_id;
  req_key.qid = ctx->qid;
  req_key.cid = ctx->cid;

  struct request_data req_data;
  req_data.start_ns = ts;
  req_data.opcode = ctx->opcode;

  long ret = bpf_map_update_elem(&in_flight, &req_key, &req_data, BPF_ANY);
  if (ret != 0) {
    // TODO(mogo): Record lost starts.
  }
  return 0;
}

SEC("tp/nvme/nvme_complete_rq")
int handle_nvme_complete_rq(struct trace_event_raw_nvme_complete_rq* ctx) {
  // bpf_printk("nvme_complete_rq");
  // bpf_printk("nvme_complete_rq: PID %d, disk=%s, qid=%d, cid=%d\n",
  //            bpf_get_current_pid_tgid() >> 32, ctx->disk, ctx->qid,
  //            ctx->cid);

  // Important to initialize the key, outherwise garbage padding (probably) may
  // lead to lookup failures.
  struct request_key req_key = {};
  req_key.ctrl_id = ctx->ctrl_id;
  req_key.qid = ctx->qid;
  req_key.cid = ctx->cid;

  struct request_data* req_data;
  req_data = bpf_map_lookup_elem(&in_flight, &req_key);
  if (req_data == NULL) {
    // TODO(mogo): Record missed starts. We expect some missing entries at the
    // very beginning on the operation, but a continuous increase may indicate
    // either logic errors or in-flight map overflow.
    return 0;
  }
  u64 ts = bpf_ktime_get_ns();

  struct latency_hist_key hist_key = {};
  hist_key.ctrl_id = ctx->ctrl_id;
  hist_key.opcode = req_data->opcode;

  struct latency_hist* hist;
  hist = bpf_map_lookup_elem(&hists, &hist_key);
  if (hist == NULL) {
    struct latency_hist new_hist = {};
    bpf_map_update_elem(&hists, &hist_key, &new_hist, BPF_ANY);
    hist = bpf_map_lookup_elem(&hists, &hist_key);
    if (!hist) {
      // TODO(mogo): Record histogram overflow.
      goto cleanup;
    }
  }
  u64 delta_us = (ts - req_data->start_ns) / 1000;
  int slot = bpf_log2l(delta_us);
  if (slot < LATENCY_MAX_SLOTS) {
    __sync_fetch_and_add(&hist->slots[slot], 1);
  }
  __sync_fetch_and_add(&hist->total_count, 1);
  __sync_fetch_and_add(&hist->total_sum, delta_us);

cleanup:
  bpf_map_delete_elem(&in_flight, &req_key);
  return 0;
}
