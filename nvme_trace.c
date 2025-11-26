#include "nvme_trace.h"

#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "nvme_trace.skel.h"

/*
make nvme_trace
sudo ./nvme_trace
*/

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static int handle_nvme_event(void* ctx, void* data, size_t data_sz) {
  const struct nvme_trace_event* my_nvme_event = data;
  if (data_sz < sizeof(struct nvme_trace_event)) {
    return -1;
  }

  if (my_nvme_event->action == kActionTypeSubmit) {
    if (data_sz < sizeof(struct nvme_submit_trace_event)) {
      return -1;
    }
    const struct nvme_submit_trace_event* se = data;
    printf(
        "Submit nvme%d: qid=%d, cmdid=%u, nsid=%u, flags=0x%x, meta=0x%x, "
        "opcode=%d\n",
        se->ctrl_id, se->qid, se->cid, se->nsid, se->flags, se->metadata,
        se->opcode);

  } else if (my_nvme_event->action == kActionTypeComplete) {
    if (data_sz < sizeof(struct nvme_complete_trace_event)) {
      return -1;
    }
    const struct nvme_complete_trace_event* ce = data;
    printf(
        "Complete nvme%d: qid=%d, cmdid=%u, res=%#llx, retries=%u, flags=0x%x, "
        "status=%#x\n",
        ce->ctrl_id, ce->qid, ce->cid, ce->result, ce->retries, ce->flags,
        ce->status);

  } else {
    printf("Unknown nvme event type: %d\n", my_nvme_event->action);
  }

  return 0;
}

int main(int argc, char** argv) {
  struct ring_buffer* nvme_trace_events = NULL;
  struct nvme_trace_bpf* skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = nvme_trace_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = nvme_trace_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  err = nvme_trace_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  nvme_trace_events =
      ring_buffer__new(bpf_map__fd(skel->maps.nvme_trace_events),
                       handle_nvme_event, /*ctx=*/NULL, /*opts=*/NULL);
  if (!nvme_trace_events) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  printf("Successfully started!\n");

  while (!exiting) {
    err = ring_buffer__poll(nvme_trace_events, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  ring_buffer__free(nvme_trace_events);
  nvme_trace_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}
