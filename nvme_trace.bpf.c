// vmlinux overlaps with nvme_core which we need for nvme trace data structures
// #include "vmlinux.h"
// clang-format off
#include "nvme_core_gen.h"
typedef _Bool bool;
// clang-format on
#include "nvme_trace.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "MIT";

#define ALL_CTRL_ID 0xFFFFFFFF
const volatile __u32 filter_ctrl_id = ALL_CTRL_ID;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} nvme_trace_events SEC(".maps");

SEC("tp/nvme/nvme_setup_cmd")
int handle_nvme_setup_cmd(struct trace_event_raw_nvme_setup_cmd* ctx) {
  // bpf_printk("nvme_setup_cmd: PID %d, qid=%d, cid=%d, opcode=0x%x\n",
  //            bpf_get_current_pid_tgid() >> 32, ctx->qid, ctx->cid,
  //            ctx->opcode);
  if (filter_ctrl_id != ALL_CTRL_ID && ctx->ctrl_id != (int)filter_ctrl_id) {
    return 0;
  }
  struct nvme_submit_trace_event* e;
  e = bpf_ringbuf_reserve(&nvme_trace_events, sizeof(*e), 0);
  if (!e) return 0;

  e->action = kActionTypeSubmit;
	e->ts_ns = bpf_ktime_get_ns();
  e->ctrl_id = ctx->ctrl_id;
  e->qid = ctx->qid;
  e->opcode = ctx->opcode;
  e->flags = ctx->flags;
  e->cid = ctx->cid;
  e->nsid = ctx->nsid;
  e->metadata = ctx->metadata;
  e->fctype = ctx->fctype;
  // Copying string doesn't quite work yet.
  // bpf_probe_read_str(e->disk, sizeof(e->disk), ctx->disk);
  // bpf_probe_read(e->cdw10, sizeof(ctx->cdw10), ctx->cdw10);

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/nvme/nvme_complete_rq")
int handle_nvme_complete_rq(struct trace_event_raw_nvme_complete_rq* ctx) {
  // bpf_printk("nvme_complete_rq: PID %d, disk=%s, qid=%d, cid=%d\n",
  //            bpf_get_current_pid_tgid() >> 32, ctx->disk, ctx->qid,
  //            ctx->cid);
  if (filter_ctrl_id != ALL_CTRL_ID && ctx->ctrl_id != (int)filter_ctrl_id) {
    return 0;
  }
  struct nvme_complete_trace_event* e;
  e = bpf_ringbuf_reserve(&nvme_trace_events, sizeof(*e), 0);
  if (!e) return 0;

  e->action = kActionTypeComplete;
	e->ts_ns = bpf_ktime_get_ns();
  // bpf_probe_read_str(e->disk, sizeof(e->disk), ctx->disk);
  e->ctrl_id = ctx->ctrl_id;
  e->qid = ctx->qid;
  e->cid = ctx->cid;
  e->result = ctx->result;
  e->retries = ctx->retries;
  e->flags = ctx->flags;
  e->status = ctx->status;

  bpf_ringbuf_submit(e, 0);
  return 0;
}
