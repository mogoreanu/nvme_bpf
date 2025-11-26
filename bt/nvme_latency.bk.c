/*
 * nvme_latency.bpf.c
 *
 * eBPF program to trace NVMe I/O latency and present it as a histogram.
 * It hooks nvme_setup_cmd (start) and nvme_complete_rq (end).
 *
 * Based on libbpf-bootstrap.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Define the maximum number of histogram slots (log2(microseconds))
#define MAX_SLOTS 27 // Up to 2^26 us = 67 seconds

char LICENSE[] SEC("license") = "GPL";

/*
 * Map to store start timestamps.
 * Key: struct request * (pointer to the I/O request)
 * Value: u64 (start timestamp in nanoseconds)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, u64);
} start_times SEC(".maps");

/*
 * Map to store the histogram.
 * We use a PERCPU_ARRAY with a single element (key = 0).
 * The value is a struct containing an array of 64-bit counters,
 * one for each histogram slot.
 */
struct hist {
	u64 slots[MAX_SLOTS];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hist);
} hist_map SEC(".maps");

/*
 * Kprobe attached to nvme_setup_cmd
 * This is our "start" event. We record the current time and
 * store it in the `start_times` map using the request pointer
 * as the key.
 */
SEC("kprobe/nvme_setup_cmd")
int BPF_KPROBE(handle_nvme_setup_cmd, struct nvme_cmd *cmd, struct request *rq)
{
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &rq, &ts, BPF_ANY);
	return 0;
}

/*
 * Kprobe attached to nvme_complete_rq
 * This is our "end" event.
 */
SEC("kprobe/nvme_complete_rq")
int BPF_KPROBE(handle_nvme_complete_rq, struct request *rq)
{
	u64 *start_ts_ns;
	u64 delta_ns;
	u64 delta_us;
	u32 slot;
	u32 zero = 0;
	struct hist *h;

	// 1. Find the start timestamp for this request
	start_ts_ns = bpf_map_lookup_elem(&start_times, &rq);
	if (!start_ts_ns) {
		return 0; // We missed the start event, ignore
	}

	delta_ns = bpf_ktime_get_ns() - *start_ts_ns;

	// 2. Clean up the start_times map to free space
	bpf_map_delete_elem(&start_times, &rq);

	// 3. Calculate the histogram slot
	delta_us = delta_ns / 1000;
	slot = bpf_log2l(delta_us);
	if (slot >= MAX_SLOTS) {
		slot = MAX_SLOTS - 1; // Clamp to the highest bucket
	}

	// 4. Find the histogram and increment the correct slot
	h = bpf_map_lookup_elem(&hist_map, &zero);
	if (h) {
		// Use atomic add for per-CPU safety
		__sync_fetch_and_add(&h->slots[slot], 1);
	}

	return 0;
}
