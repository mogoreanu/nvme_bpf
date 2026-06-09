#include "nvme_trace.h"

#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/flags.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "nvme_strings.h"
#include "nvme_trace.skel.h"
#include "nvme_trace_vlog_bpf.skel.h"

/*
bazel build :nvme_trace && sudo $(pwd)/bazel-bin/nvme_trace
*/

ABSL_DECLARE_FLAG(int, stderrthreshold);
ABSL_FLAG(int, ctrl_id, -1,
          "NVMe controller ID to filter on, -1 for all controllers");

ABSL_FLAG(bool, bpf_trace, false,
          "If set will load a program that includes bpf_printk. Requires a "
          "kernel built with CONFIG_TRACING and CONFIG_BPF_EVENTS. To display "
          "the events cat /sys/kernel/debug/tracing/trace_pipe");

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
  std::string_view disk(se.disk, strnlen(se.disk, sizeof(se.disk)));
  if (se.qid == 0) {
    std::cout << std::dec << se.ts_ns << " " << disk << " Submit nvme"
              << std::dec << se.ctrl_id << ": qid=" << se.qid
              << ", cid=" << se.cid << ", nsid=" << se.nsid << ", flags=0x"
              << std::hex << static_cast<int>(se.flags) << ", meta=0x"
              << std::hex << static_cast<int>(se.metadata)
              << ", opcode=" << std::dec << static_cast<int>(se.opcode) << " ("
              << nvme_abi::NvmeAdminOpcodeToString(
                     static_cast<nvme_abi::NvmeOpcode>(se.opcode))
              << ")"
              << ", cdw10=0x"
              << absl::BytesToHexString(std::string_view(
                     reinterpret_cast<const char*>(se.cdw10), sizeof(se.cdw10)))
              << std::endl;
  } else {
    std::cout << std::dec << se.ts_ns << " " << disk << " Submit nvme"
              << std::dec << se.ctrl_id << ": qid=" << se.qid
              << ", cid=" << se.cid << ", nsid=" << se.nsid << ", flags=0x"
              << std::hex << static_cast<int>(se.flags) << ", meta=0x"
              << std::hex << static_cast<int>(se.metadata)
              << ", opcode=" << std::dec << static_cast<int>(se.opcode) << " ("
              << nvme_abi::NvmeIoOpcodeToString(
                     static_cast<nvme_abi::NvmeOpcode>(se.opcode))
              << ")" << std::endl;
    // TODO(mogo): cdw10 seems to be populated with garbage.
    // << ", cdw10=0x" << absl::BytesToHexString(std::string_view(
    //        reinterpret_cast<const char*>(se.cdw10), sizeof(se.cdw10)))
  }
  return 0;
}

int HandleNvmeCompleteEvent(const nvme_complete_trace_event& ce) {
  std::string_view disk(ce.disk, strnlen(ce.disk, sizeof(ce.disk)));
  std::cout << std::dec << ce.ts_ns << " " << disk << " Complete nvme"
            << std::dec << ce.ctrl_id << ": qid=" << ce.qid
            << ", cid=" << ce.cid << ", res=0x" << std::hex << ce.result
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

template <typename TSkel>
absl::Status RunMain() {
  struct ring_buffer* nvme_trace_events;
  TSkel* skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  LIBBPF_OPTS(bpf_object_open_opts, open_opts, .kernel_log_level = 2, );
  skel = TSkel::open(&open_opts);
  if (skel == nullptr) {
    return absl::InternalError("Failed to open and load BPF skeleton");
  }
  auto skel_destroy_cleanup =
      absl::MakeCleanup([skel]() { TSkel::destroy(skel); });

  auto filter_ctrl_id = absl::GetFlag(FLAGS_ctrl_id);
  if (filter_ctrl_id >= 0) {
    skel->rodata->filter_ctrl_id = filter_ctrl_id;
  }

  size_t log_buf_sz = 1024 * 1024;
  char* setup_log_buf = (char*)malloc(log_buf_sz);
  char* complete_log_buf = (char*)malloc(log_buf_sz);
  if (setup_log_buf) {
    setup_log_buf[0] = '\0';
    bpf_program__set_log_buf(skel->progs.handle_nvme_setup_cmd, setup_log_buf,
                             log_buf_sz);
    bpf_program__set_log_level(skel->progs.handle_nvme_setup_cmd, 1);
  }
  if (complete_log_buf) {
    complete_log_buf[0] = '\0';
    bpf_program__set_log_buf(skel->progs.handle_nvme_complete_rq,
                             complete_log_buf, log_buf_sz);
    bpf_program__set_log_level(skel->progs.handle_nvme_complete_rq, 1);
  }
  auto free_logs_cleanup =
      absl::MakeCleanup([setup_log_buf, complete_log_buf]() {
        free(setup_log_buf);
        free(complete_log_buf);
      });

  err = TSkel::load(skel);
  if (err) {
    if (setup_log_buf && setup_log_buf[0]) {
      std::cerr << "Verifier log for handle_nvme_setup_cmd:\n"
                << setup_log_buf << std::endl;
    }
    if (complete_log_buf && complete_log_buf[0]) {
      std::cerr << "Verifier log for handle_nvme_complete_rq:\n"
                << complete_log_buf << std::endl;
    }
    return absl::InternalError(
        absl::StrCat("Failed to load and verify BPF skeleton, err=", err));
  }

  err = TSkel::attach(skel);
  if (err) {
    return absl::InternalError(
        absl::StrCat("Failed to attach BPF skeleton, err=", err));
  }
  auto skel_detach_cleanup =
      absl::MakeCleanup([skel]() { TSkel::detach(skel); });

  /* Set up ring buffer polling */
  nvme_trace_events =
      ring_buffer__new(bpf_map__fd(skel->maps.nvme_trace_events),
                       HandleNvmeEvent, /*ctx=*/nullptr, /*opts=*/nullptr);
  if (!nvme_trace_events) {
    return absl::InternalError("Failed to create ring buffer");
  }
  auto ringbuf_free_cleanup = absl::MakeCleanup(
      [&nvme_trace_events]() { ring_buffer__free(nvme_trace_events); });

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

  return absl::OkStatus();
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  absl::Status status;
  if (absl::GetFlag(FLAGS_bpf_trace)) {
    status = RunMain<nvme_trace_vlog_bpf>();
  } else {
    status = RunMain<nvme_trace_bpf>();
  }
  if (!status.ok()) {
    LOG(ERROR) << "Error: " << status;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
