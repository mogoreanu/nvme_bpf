# nvme_bpf
Tools to debug and monitor linux NVMe activity using BPF / eBPF tracepoints / kprobes

## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

You will need `bpftool` during the build process to generate the BPF skeleton 
files and core dependencies.

TODO(mogo): It would be nice to add bpftool to submodules and build it from 
scratch.

```shell
apt install clang libelf1 libelf-dev zlib1g-dev
apt install bpftool
```

You may have to make bpftool available for non-root users
```shell
cp /usr/sbin/bpftool /usr/bin/
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

## More notes

To re-generate the `nvme_core.h` file use `bpftool`

```shell
bpftool btf dump file /sys/kernel/btf/nvme_core format c > nvme_core.h
```

To re-generate the `vmlinux.h` file use `bpftool`

```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

# Relevant projects

* https://github.com/iovisor/bcc - contains a bunch of examples, in particular 
the examples in `libbpf-tools` are applicable here.
* https://github.com/libbpf/libbpf-bootstrap
* https://github.com/jackhumphries/bazel-ebpf
* https://docs.ebpf.io/