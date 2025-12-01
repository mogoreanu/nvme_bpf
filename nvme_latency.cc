#include "nvme_latency.h"

#include <argp.h>
#include <bpf/bpf.h>
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
bazel build :nvme_latency && sudo bazel-bin/nvme_latency --stderrthreshold=0
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

absl::Status PrintAllHists(struct nvme_latency_bpf* skel) {
  int fd = bpf_map__fd(skel->maps.hists);
  if (fd < 0) {
    if (fd == -1) {
      std::cerr << "BPF latency histogram map not created. " << std::endl;
    } else {
      std::cerr << "BPF latency histogram map error. err=" << fd << std::endl;
    }
    return absl::InternalError("BPF map fd error");
  }
  struct latency_hist hist;

  struct latency_hist_key lookup_key;
  lookup_key.ctrl_id = std::numeric_limits<u32>::max();
  lookup_key.opcode = 0;
  struct latency_hist_key next_key;

  if (bpf_map_get_next_key(fd, &lookup_key, &next_key) != 0) {
    std::cout << "No entries in histogram map." << std::endl;
    return absl::OkStatus();
  }

  while (0 == bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    std::cout << "key: ctrl_id=" << next_key.ctrl_id
              << ", opcode=" << next_key.opcode << std::endl;
    int err = bpf_map_lookup_elem(fd, &next_key, &hist);
    if (err < 0) {
      std::cerr << "Histogram not found for key." << std::endl;
      break;
    }
    lookup_key = next_key;
  }
  return absl::OkStatus();
}

absl::Status PrintAllInFlight(struct nvme_latency_bpf* skel) {
  int fd = bpf_map__fd(skel->maps.in_flight);
  if (fd < 0) {
    if (fd == -1) {
      std::cerr << "BPF in-flight map not created. " << std::endl;
    } else {
      std::cerr << "BPF in-flight map error. err=" << fd << std::endl;
    }
    return absl::InternalError("BPF map fd error");
  }
  struct request_data rdata;

  struct request_key rkey;
  rkey.ctrl_id = std::numeric_limits<u32>::max();
  rkey.qid = 0;
  rkey.cid = 0;
  struct request_key rnkey;

  uint32_t in_flight_count = 0;

  if (bpf_map_get_next_key(fd, &rkey, &rnkey) != 0) {
    std::cout << "No entries in in-flight request map." << std::endl;
    return absl::OkStatus();
  }

  while (0 == bpf_map_get_next_key(fd, &rkey, &rnkey)) {
    // std::cout << "key: ctrl_id=" << rkey.ctrl_id
    //           << ", qid=" << rkey.qid
    //           << ", cid=" << rkey.cid << std::endl;
              ++in_flight_count;
    int err = bpf_map_lookup_elem(fd, &rnkey, &rdata);
    if (err < 0) {
      std::cerr << "Histogram not found for key." << std::endl;
      break;
    }
    rkey = rnkey;
  }
  std::cout << "Total in-flight requests: " << in_flight_count << std::endl;
  return absl::OkStatus();
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
    absl::SleepFor(absl::Seconds(1));
    do {
      int fd = bpf_map__fd(skel->maps.hists);
      if (fd < 0) {
        if (fd == -1) {
          std::cerr << "BPF latency histogram map not created. " << std::endl;
        } else {
          std::cerr << "BPF latency histogram map error. err=" << fd
                    << std::endl;
        }
        break;
      }
      struct latency_hist hist;

      struct latency_hist_key lookup_key = {};
      lookup_key.ctrl_id = 0;
      lookup_key.opcode = 0;
      int r = bpf_map_lookup_elem(fd, &lookup_key, &hist);
      if (r < 0) {
        std::cout << "Failed to find the histogram by key." << std::endl;
        PrintAllHists(skel).IgnoreError();
        PrintAllInFlight(skel).IgnoreError();
        break;
      }
      std::cout << "" << hist.slots[0] << std::endl;
      //   struct latency_hist_key next_key;
      //   while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
      //     err = bpf_map_lookup_elem(fd, &next_key, &hist);
      //     if (err < 0) {
      //       fprintf(stderr, "failed to lookup hist: %d\n", err);
      //       return -1;
      //     }
      //     if (env.per_disk) {
      //       partition = partitions__get_by_dev(partitions, next_key.dev);
      //       printf("\ndisk = %s\t", partition ? partition->name : "Unknown");
      //     }
      //     if (env.per_flag) print_cmd_flags(next_key.cmd_flags);
      //     printf("\n");
      //     print_log2_hist(hist.slots, MAX_SLOTS, units);
      //     lookup_key = next_key;
      //   }
    } while (false);
  }

cleanup:
  nvme_latency_bpf__destroy(skel);
  return err < 0 ? -err : EXIT_SUCCESS;
}
