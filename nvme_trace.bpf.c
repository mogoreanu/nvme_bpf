// vmlinux overlaps with nvme_core which we need for nvme trace data structures
// #include "vmlinux.h"
// clang-format off
#include "nvme_core.h"
// clang-format on
#include "nvme_trace.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Apache";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} nvme_trace_events SEC(".maps");

// clang-format off
/*
This tracepoint is hit when an NVMe command is prepared.

cat /sys/kernel/debug/tracing/events/nvme/nvme_setup_cmd/format
name: nvme_setup_cmd
ID: 1503
format:
  field:unsigned short common_type;  offset:0;  size:2;  signed:0;
  field:unsigned char common_flags;  offset:2;  size:1;  signed:0;
  field:unsigned char common_preempt_count;  offset:3;  size:1;  signed:0;
  field:int common_pid;  offset:4;  size:4;  signed:1;

  field:char disk[32];  offset:8;  size:32;  signed:0;
  field:int ctrl_id;  offset:40;  size:4;  signed:1;
  field:int qid;  offset:44;  size:4;  signed:1;
  field:u8 opcode;  offset:48;  size:1;  signed:0;
  field:u8 flags;  offset:49;  size:1;  signed:0;
  field:u8 fctype;  offset:50;  size:1;  signed:0;
  field:u16 cid;  offset:52;  size:2;  signed:0;
  field:u32 nsid;  offset:56;  size:4;  signed:0;
  field:bool metadata;  offset:60;  size:1;  signed:0;
  field:u8 cdw10[24];  offset:61;  size:24;  signed:0;

print fmt: "nvme%d: %sqid=%d, cmdid=%u, nsid=%u, flags=0x%x, meta=0x%x, cmd=(%s %s)", REC->ctrl_id, nvme_trace_disk_name(p, REC->disk), REC->qid, REC->cid, REC->nsid, REC->flags, REC->metadata, ((REC->opcode) == nvme_fabrics_command ? __print_symbolic(REC->fctype, { nvme_fabrics_type_property_set, "nvme_fabrics_type_property_set" }, { nvme_fabrics_type_connect, "nvme_fabrics_type_connect" }, { nvme_fabrics_type_property_get, "nvme_fabrics_type_property_get" }, { nvme_fabrics_type_auth_send, "nvme_fabrics_type_auth_send" }, { nvme_fabrics_type_auth_receive, "nvme_fabrics_type_auth_receive" }) : ((REC->qid) ? __print_symbolic(REC->opcode, { nvme_cmd_flush, "nvme_cmd_flush" }, { nvme_cmd_write, "nvme_cmd_write" }, { nvme_cmd_read, "nvme_cmd_read" }, { nvme_cmd_write_uncor, "nvme_cmd_write_uncor" }, { nvme_cmd_compare, "nvme_cmd_compare" }, { nvme_cmd_write_zeroes, "nvme_cmd_write_zeroes" }, { nvme_cmd_dsm, "nvme_cmd_dsm" }, { nvme_cmd_verify, "nvme_cmd_verify" }, { nvme_cmd_resv_register, "nvme_cmd_resv_register" }, { nvme_cmd_resv_report, "nvme_cmd_resv_report" }, { nvme_cmd_resv_acquire, "nvme_cmd_resv_acquire" }, { nvme_cmd_resv_release, "nvme_cmd_resv_release" }, { nvme_cmd_zone_mgmt_send, "nvme_cmd_zone_mgmt_send" }, { nvme_cmd_zone_mgmt_recv, "nvme_cmd_zone_mgmt_recv" }, { nvme_cmd_zone_append, "nvme_cmd_zone_append" }) : __print_symbolic(REC->opcode, { nvme_admin_delete_sq, "nvme_admin_delete_sq" }, { nvme_admin_create_sq, "nvme_admin_create_sq" }, { nvme_admin_get_log_page, "nvme_admin_get_log_page" }, { nvme_admin_delete_cq, "nvme_admin_delete_cq" }, { nvme_admin_create_cq, "nvme_admin_create_cq" }, { nvme_admin_identify, "nvme_admin_identify" }, { nvme_admin_abort_cmd, "nvme_admin_abort_cmd" }, { nvme_admin_set_features, "nvme_admin_set_features" }, { nvme_admin_get_features, "nvme_admin_get_features" }, { nvme_admin_async_event, "nvme_admin_async_event" }, { nvme_admin_ns_mgmt, "nvme_admin_ns_mgmt" }, { nvme_admin_activate_fw, "nvme_admin_activate_fw" }, { nvme_admin_download_fw, "nvme_admin_download_fw" }, { nvme_admin_dev_self_test, "nvme_admin_dev_self_test" }, { nvme_admin_ns_attach, "nvme_admin_ns_attach" }, { nvme_admin_keep_alive, "nvme_admin_keep_alive" }, { nvme_admin_directive_send, "nvme_admin_directive_send" }, { nvme_admin_directive_recv, "nvme_admin_directive_recv" }, { nvme_admin_virtual_mgmt, "nvme_admin_virtual_mgmt" }, { nvme_admin_nvme_mi_send, "nvme_admin_nvme_mi_send" }, { nvme_admin_nvme_mi_recv, "nvme_admin_nvme_mi_recv" }, { nvme_admin_dbbuf, "nvme_admin_dbbuf" }, { nvme_admin_format_nvm, "nvme_admin_format_nvm" }, { nvme_admin_security_send, "nvme_admin_security_send" }, { nvme_admin_security_recv, "nvme_admin_security_recv" }, { nvme_admin_sanitize_nvm, "nvme_admin_sanitize_nvm" }, { nvme_admin_get_lba_status, "nvme_admin_get_lba_status" }))), ((REC->opcode) == nvme_fabrics_command ? nvme_trace_parse_fabrics_cmd(p, REC->fctype, REC->cdw10) : ((REC->qid) ? nvme_trace_parse_nvm_cmd(p, REC->opcode, REC->cdw10) : nvme_trace_parse_admin_cmd(p, REC->opcode, REC->cdw10)))
*/
// clang-format on

SEC("tp/nvme/nvme_setup_cmd")
int handle_nvme_setup_cmd(struct trace_event_raw_nvme_setup_cmd* ctx) {
  // bpf_printk("nvme_setup_cmd: PID %d, qid=%d, cid=%d, opcode=0x%x\n",
  //            bpf_get_current_pid_tgid() >> 32, ctx->qid, ctx->cid,
  //            ctx->opcode);
  struct nvme_submit_trace_event* e;
  e = bpf_ringbuf_reserve(&nvme_trace_events, sizeof(*e), 0);
  if (!e) return 0;

  e->action = kActionTypeSubmit;
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

// clang-format off
/*
cat /sys/kernel/debug/tracing/events/nvme/nvme_complete_rq/format

name: nvme_complete_rq
ID: 1540
format:
  field:unsigned short common_type;  offset:0;  size:2;  signed:0;
  field:unsigned char common_flags;  offset:2;  size:1;  signed:0;
  field:unsigned char common_preempt_count;  offset:3;  size:1;  signed:0;
  field:int common_pid;  offset:4;  size:4;  signed:1;

  field:char disk[32];  offset:8;  size:32;  signed:0;
  field:int ctrl_id;  offset:40;  size:4;  signed:1;
  field:int qid;  offset:44;  size:4;  signed:1;
  field:int cid;  offset:48;  size:4;  signed:1;
  field:u64 result;  offset:56;  size:8;  signed:0;
  field:u8 retries;  offset:64;  size:1;  signed:0;
  field:u8 flags;  offset:65;  size:1;  signed:0;
  field:u16 status;  offset:66;  size:2;  signed:0;

print fmt: "nvme%d: %sqid=%d, cmdid=%u, res=%#llx, retries=%u, flags=0x%x, status=%#x", REC->ctrl_id, nvme_trace_disk_name(p, REC->disk), REC->qid, REC->cid, REC->result, REC->retries, REC->flags, REC->status
*/
// clang-format on
SEC("tp/nvme/nvme_complete_rq")
int handle_nvme_complete_rq(struct trace_event_raw_nvme_complete_rq* ctx) {
  // bpf_printk("nvme_complete_rq: PID %d, disk=%s, qid=%d, cid=%d\n",
  //            bpf_get_current_pid_tgid() >> 32, ctx->disk, ctx->qid,
  //            ctx->cid);
  struct nvme_complete_trace_event* e;
  e = bpf_ringbuf_reserve(&nvme_trace_events, sizeof(*e), 0);
  if (!e) return 0;

  e->action = kActionTypeComplete;
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
