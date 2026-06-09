I have a bazel built c++ binary @nvme_trace.cc that loads a BPF program
@nvme_trace.bpf.c and then organizes communication between the BPF program and the loading program using `nvme_trace_events` ring buffer.
