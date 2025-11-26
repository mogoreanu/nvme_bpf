#include "nvme_trace.h"

#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_join.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "nvme_trace.skel.h"

/*
bazel build :nvme_trace && sudo bazel-bin/nvme_trace
*/

ABSL_DECLARE_FLAG(int, stderrthreshold);

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  if (absl::GetFlag(FLAGS_stderrthreshold) == 0 || ABSL_VLOG_IS_ON(1)) {
    return vfprintf(stderr, format, args);
  }
  return 0;
  // TODO(mogo): Can't get rid of the trailing newlines properly.
  //   std::string buf;
  //   buf.resize(256);
  //   int r = vsnprintf(buf.data(), buf.size(), format, args);
  //   if (r < 0) {
  //     LOG(ERROR) << "Failed to print libbpf log message";
  //     return 0;
  //   }
  //   absl::StripAsciiWhitespace(&buf);
  //   auto stripped_buf = absl::StripSuffix(buf, "\n");
  //   stripped_buf = absl::StripSuffix(stripped_buf, "\r");
  //   stripped_buf = absl::StripSuffix(stripped_buf, "\n");
  //   uint ur = r;
  //   if (ur < buf.size()) {
  //     LOG(INFO) << stripped_buf;
  //   } else {
  //     LOG(INFO) << stripped_buf << "...(truncated)";
  //   }
  //   return 0;
}

int HandleNvmeSubmitEvent(const nvme_submit_trace_event& se) {
  std::cout << "Submit nvme" << se.ctrl_id << ": qid=" << se.qid
            << ", cmdid=" << se.cid << ", nsid=" << se.nsid << ", flags=0x"
            << std::hex << static_cast<int>(se.flags) << ", meta=0x" << std::hex
            << static_cast<int>(se.metadata) << ", opcode=" << std::dec
            << static_cast<int>(se.opcode) << std::endl;
  return 0;
}

int HandleNvmeCompleteEvent(const nvme_complete_trace_event& ce) {
  std::cout << "Complete nvme" << ce.ctrl_id << ": qid=" << ce.qid
            << ", cmdid=" << ce.cid << ", res=0x" << std::hex << ce.result
            << ", retries=" << std::dec << static_cast<int>(ce.retries)
            << ", flags=0x" << std::hex << static_cast<int>(ce.flags)
            << ", status=0x" << std::hex << ce.status << std::endl;
  return 0;
}

int HandleNvmeEvent(void* ctx, void* data, size_t data_sz) {
  const struct nvme_trace_event* my_nvme_event =
      reinterpret_cast<nvme_trace_event*>(data);
  if (data_sz < sizeof(struct nvme_trace_event)) {
    return -1;
  }

  if (my_nvme_event->action == kActionTypeSubmit) {
    if (data_sz < sizeof(struct nvme_submit_trace_event)) {
      return -1;
    }
    const struct nvme_submit_trace_event* se =
        reinterpret_cast<nvme_submit_trace_event*>(data);
    return HandleNvmeSubmitEvent(*se);
  } else if (my_nvme_event->action == kActionTypeComplete) {
    if (data_sz < sizeof(struct nvme_complete_trace_event)) {
      return -1;
    }
    const struct nvme_complete_trace_event* ce =
        reinterpret_cast<nvme_complete_trace_event*>(data);
    return HandleNvmeCompleteEvent(*ce);
  } else {
    printf("Unknown nvme event type: %d\n", my_nvme_event->action);
  }

  return 0;
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  struct ring_buffer* nvme_trace_events = NULL;
  struct nvme_trace_bpf* skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = nvme_trace_bpf__open();
  if (skel == nullptr) {
    LOG(ERROR) << "Failed to open and load BPF skeleton" << std::endl;
    return EXIT_FAILURE;
  }

  err = nvme_trace_bpf__load(skel);
  if (err) {
    LOG(ERROR) << "Failed to load and verify BPF skeleton, err=" << err
               << std::endl;
    goto cleanup;
  }

  err = nvme_trace_bpf__attach(skel);
  if (err) {
    LOG(ERROR) << "Failed to attach BPF skeleton, err=" << err << std::endl;
    goto cleanup;
  }

  /* Set up ring buffer polling */
  nvme_trace_events =
      ring_buffer__new(bpf_map__fd(skel->maps.nvme_trace_events),
                       HandleNvmeEvent, /*ctx=*/nullptr, /*opts=*/nullptr);
  if (!nvme_trace_events) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  std::cout << "Successfully started!" << std::endl;

  while (!exiting) {
    err = ring_buffer__poll(nvme_trace_events, /*timeout_ms=*/100);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      std::cout << "Error polling perf buffer: " << err << std::endl;
      break;
    }
  }

cleanup:
  ring_buffer__free(nvme_trace_events);
  nvme_trace_bpf__destroy(skel);
  return err < 0 ? -err : EXIT_SUCCESS;
}
