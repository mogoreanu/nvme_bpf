#include "nvme_latency.h"

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
#include "nvme_latency.skel.h"

/*
bazel build :nvme_latency && sudo bazel-bin/nvme_latency
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
}



int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  struct nvme_latency_bpf* skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = nvme_latency_bpf__open();
  if (skel == nullptr) {
    LOG(ERROR) << "Failed to open and load BPF skeleton" << std::endl;
    return EXIT_FAILURE;
  }

  err = nvme_latency_bpf__load(skel);
  if (err) {
    LOG(ERROR) << "Failed to load and verify BPF skeleton, err=" << err
               << std::endl;
    goto cleanup;
  }

  err = nvme_latency_bpf__attach(skel);
  if (err) {
    LOG(ERROR) << "Failed to attach BPF skeleton, err=" << err << std::endl;
    goto cleanup;
  }

  std::cout << "Successfully started!" << std::endl;

  while (!exiting) {
    absl::SleepFor(absl::Milliseconds(10));
  }

cleanup:
  nvme_latency_bpf__destroy(skel);
  return err < 0 ? -err : EXIT_SUCCESS;
}
