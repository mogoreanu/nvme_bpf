// clang-format off
#include "nvme_core.h"
// clang-format on

#include "nvme_latency.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "MIT";

#define MAX_LATENCY_ENTRIES 20

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

SEC("tp/nvme/nvme_setup_cmd")
int handle_nvme_setup_cmd(struct trace_event_raw_nvme_setup_cmd* ctx) {
  u64 ts = bpf_ktime_get_ns();
  struct request_key req_key;
  req_key.ctrl_id = ctx->ctrl_id;
  req_key.qid = ctx->qid;
  req_key.cid = ctx->cid;
  struct request_data req_data;
  req_data.start_ns = ts;
  long ret = bpf_map_update_elem(&in_flight, &req_key, &req_data, BPF_ANY);
	if (ret != 0) {
		// TODO(mogo): Record lost starts.
	}
  return 0;
}

SEC("tp/nvme/nvme_complete_rq")
int handle_nvme_complete_rq(struct trace_event_raw_nvme_complete_rq* ctx) {
  struct request_key req_key;
  req_key.ctrl_id = ctx->ctrl_id;
  req_key.qid = ctx->qid;
  req_key.cid = ctx->cid;

  struct request_data* req_data;
  req_data = bpf_map_lookup_elem(&in_flight, &req_key);
  if (!req_data) {
    // TODO(mogo): Record missed starts.
    return 0;
  }
  u64 delta_ns = bpf_ktime_get_ns() - req_data->start_ns;

  struct latency_hist_key hist_key = {};
	hist_key.ctrl_id = 0;
	hist_key.opcode = 0;
  struct latency_hist* hist;
  hist = bpf_map_lookup_elem(&hists, &hist_key);
  if (!hist) {
    struct latency_hist new_hist = {};
    bpf_map_update_elem(&hists, &hist_key, &new_hist, BPF_ANY);
    hist = bpf_map_lookup_elem(&hists, &hist_key);
    if (!hist) {
      goto cleanup;
    }
  }
  int slot = 0;
  __sync_fetch_and_add(&hist->slots[slot], 1);

cleanup:
  bpf_map_delete_elem(&in_flight, &req_key);
  return 0;
}
