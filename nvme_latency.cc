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

#include "absl/cleanup/cleanup.h"
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
#include "bits.bpf.h"
#include "nvme_latency.skel.h"

/*
bazel build :nvme_latency && sudo bazel-bin/nvme_latency
bazel build :nvme_latency && sudo bazel-bin/nvme_latency --stderrthreshold=0
*/

ABSL_DECLARE_FLAG(int, stderrthreshold);

ABSL_FLAG(int, ctrl_id, -1,
          "NVMe controller ID to filter on, -1 for all controllers");

ABSL_FLAG(int, lat_min_us, -1, "");
ABSL_FLAG(int, lat_shift, -1, "");

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  if (absl::GetFlag(FLAGS_stderrthreshold) == 0 || ABSL_VLOG_IS_ON(1)) {
    return vfprintf(stderr, format, args);
  }
  return 0;
}

int global_lat_min_us = 0;
int global_lat_shift = 0;

absl::Status PrintHist(const struct latency_hist& hist) {
  int first_nonzero_slot = 0;
  while (first_nonzero_slot < LATENCY_MAX_SLOTS &&
         hist.slots[first_nonzero_slot] == 0) {
    ++first_nonzero_slot;
  }
  if (first_nonzero_slot == LATENCY_MAX_SLOTS) {
    std::cout << "  (all zero slots)" << std::endl;
    return absl::OkStatus();
  }
  int last_nonzero_slot = LATENCY_MAX_SLOTS - 1;
  while (last_nonzero_slot >= first_nonzero_slot &&
         hist.slots[last_nonzero_slot] == 0) {
    --last_nonzero_slot;
  }

  uint64_t computed_total_count = 0;

  if (hist.slots[LATENCY_MAX_SLOTS] != 0) {
    std::cout << "  ["
              << bpf_bucket_low(LATENCY_MAX_SLOTS, global_lat_min_us,
                                global_lat_shift, LATENCY_MAX_SLOTS)
              << "us - "
              << bpf_bucket_high(LATENCY_MAX_SLOTS, global_lat_min_us,
                                 global_lat_shift, LATENCY_MAX_SLOTS)
              << "us): " << hist.slots[LATENCY_MAX_SLOTS] << std::endl;
    computed_total_count += hist.slots[LATENCY_MAX_SLOTS];
  }

  for (int slot = first_nonzero_slot; slot <= last_nonzero_slot; ++slot) {
    std::cout << "  ["
              << bpf_bucket_low(slot, global_lat_min_us, global_lat_shift,
                                LATENCY_MAX_SLOTS)
              << "us - "
              << bpf_bucket_high(slot, global_lat_min_us, global_lat_shift,
                                 LATENCY_MAX_SLOTS)
              << "us): " << hist.slots[slot] << std::endl;
    computed_total_count += hist.slots[slot];
  }
  if (computed_total_count != hist.total_count) {
    std::cerr << "Warning: total_count mismatch: computed="
              << computed_total_count << ", recorded=" << hist.total_count
              << std::endl;
  }
  std::cout << "  Total count: " << hist.total_count
            << " avg=" << static_cast<double>(hist.total_sum) / hist.total_count
            << std::endl;
  return absl::OkStatus();
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
              << ", opcode=" << static_cast<int>(next_key.opcode) << std::endl;
    int err = bpf_map_lookup_elem(fd, &next_key, &hist);
    if (err < 0) {
      std::cerr << "Histogram not found for key." << std::endl;
      break;
    }

    auto ps = PrintHist(hist);
    if (!ps.ok()) {
      std::cerr << "Failed to print histogram: " << ps.message() << std::endl;
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
  auto skel_destroy_cleanup =
      absl::MakeCleanup([&skel]() { nvme_latency_bpf__destroy(skel); });

  auto filter_ctrl_id = absl::GetFlag(FLAGS_ctrl_id);
  if (filter_ctrl_id >= 0) {
    skel->rodata->filter_ctrl_id = filter_ctrl_id;
  }
  auto flag_lat_min_us = absl::GetFlag(FLAGS_lat_min_us);
  if (flag_lat_min_us >= 0) {
    skel->rodata->latency_min = flag_lat_min_us;
  }
  global_lat_min_us = skel->rodata->latency_min;

  auto flag_lat_shift = absl::GetFlag(FLAGS_lat_shift);
  if (flag_lat_shift >= 0) {
    skel->rodata->latency_shift = flag_lat_shift;
  }
  global_lat_shift = skel->rodata->latency_shift;

  err = nvme_latency_bpf__load(skel);
  if (err) {
    LOG(ERROR) << "Failed to load and verify BPF skeleton, err=" << err
               << std::endl;
    return EXIT_FAILURE;
  }

  err = nvme_latency_bpf__attach(skel);
  if (err) {
    LOG(ERROR) << "Failed to attach BPF skeleton, err=" << err << std::endl;
    return EXIT_FAILURE;
  }
  auto skel_detach_cleanup =
      absl::MakeCleanup([&skel]() { nvme_latency_bpf__detach(skel); });

  std::cout << "Successfully started!" << std::endl;

  absl::Time next_print = absl::Now() + absl::Seconds(1);
  while (!exiting) {
    auto now = absl::Now();
    if (now > next_print) {
      std::cout << "=====================" << std::endl;
      PrintAllHists(skel).IgnoreError();
      next_print = now + absl::Seconds(1);
    }
    absl::SleepFor(absl::Milliseconds(50));
  }

  return err < 0 ? -err : EXIT_SUCCESS;
}
