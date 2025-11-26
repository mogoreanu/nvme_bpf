// clang-format off
#include "nvme_core.h"
// clang-format on

#include "nvme_latency.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "MIT";

#define MAX_ENTRIES	20

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct latency_hist_key);
	__type(value, struct latency_hist);
} hists SEC(".maps");


SEC("tp/nvme/nvme_setup_cmd")
int handle_nvme_setup_cmd(struct trace_event_raw_nvme_setup_cmd* ctx) {
  return 0;
}

SEC("tp/nvme/nvme_complete_rq")
int handle_nvme_complete_rq(struct trace_event_raw_nvme_complete_rq* ctx) {
  return 0;
}
