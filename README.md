# nvme_bpf
Tools to debug and monitor linux NVMe activity using BPF / eBPF tracepoints / kprobes

## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

```shell
apt install clang libelf1 libelf-dev zlib1g-dev
```

## Getting the source code

Download the git repository and check out submodules:
```bash
git clone --recurse-submodules https://github.com/mogoreanu/nvme_bpf
```

If you happened to have cloned without `--recurse-submodules` you can update
submodules using this command:
```shell
git submodule update --init --recursive
```

## nvme_trace

The `nvme_trace` binary intercepts each NVMe SQE and CQE and prints a log entry
with the information from the commands being passed to the NVMe controller.

```shell
bazel build :nvme_trace
```

```shell
sudo bazel-bin/nvme_trace
```

## nvme_latency

The `nvme_latency` binary accumulates latency histograms per controller and 
opcode and displays them periodically in the shell.

```shell
bazel build :nvme_latency
```

```shell
sudo bazel-bin/nvme_latency
```

Useful flags
* `--ctrl_id` - filters the requests to include only the requests for the 
specified controller.
* `--nsid` - filters the requests to include only the requests for the specified
namespace.
* `--lat_min_us` - specifies the minimum interesting latency, will increase
the granularity of the data around the interesting latency.
* `--lat_shift` - specifies the size of the first bucket. With the default 
`--lat_shift` of zero the first bucket is 1us. Increasing the shift reduces the
number of buckets necessary to hold the entire interesting range.

## Tracepoints

### nvme_setup_cmd

```bash
cat /sys/kernel/debug/tracing/events/nvme/nvme_setup_cmd/format
name: nvme_setup_cmd
ID: 1541
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:char disk[32];	offset:8;	size:32;	signed:0;
	field:int ctrl_id;	offset:40;	size:4;	signed:1;
	field:int qid;	offset:44;	size:4;	signed:1;
	field:u8 opcode;	offset:48;	size:1;	signed:0;
	field:u8 flags;	offset:49;	size:1;	signed:0;
	field:u8 fctype;	offset:50;	size:1;	signed:0;
	field:u16 cid;	offset:52;	size:2;	signed:0;
	field:u32 nsid;	offset:56;	size:4;	signed:0;
	field:bool metadata;	offset:60;	size:1;	signed:0;
	field:u8 cdw10[24];	offset:61;	size:24;	signed:0;
```

Example C data structure
```c
struct trace_event_raw_nvme_setup_cmd {
	struct trace_entry ent;
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
	char __data[0];
};
```

### nvme_complete_rq

```bash
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

```

Example C data structure
```c
struct trace_event_raw_nvme_complete_rq {
	struct trace_entry ent;
	char disk[32];
	int ctrl_id;
	int qid;
	int cid;
	u64 result;
	u8 retries;
	u8 flags;
	u16 status;
	char __data[0];
};
```

## More notes

The `nvme_core_gen.h` is generated using `bpftool`

```shell
# Using installed bpftool
bpftool btf dump file /sys/kernel/btf/nvme_core format c
# Using built bpftool
bazel run :bpftool -- btf dump file /sys/kernel/btf/nvme_core format c
```

To re-generate the `vmlinux.h` file use `bpftool`

```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c
bazel run :bpftool -- btf dump file /sys/kernel/btf/vmlinux format c
```

# Relevant projects

* https://github.com/iovisor/bcc - contains a bunch of examples, in particular 
the examples in `libbpf-tools` are applicable here.
* https://github.com/libbpf/libbpf-bootstrap
* https://github.com/jackhumphries/bazel-ebpf
* https://docs.ebpf.io/