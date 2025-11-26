# nvme_bpf
Tools to debug and monitor linux NVMe activity using BPF / eBPF tracepoints / kprobes

# Building


## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

## Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/mogoreanu/nvme_bpf
```
