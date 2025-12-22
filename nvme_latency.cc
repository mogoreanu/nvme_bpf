#include "nvme_latency.h"

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <unordered_set>
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
#include "histogram.bpf.h"
#include "histogram.h"
#include "nvme_abi.h"
#include "nvme_latency_bpf.skel.h"
#include "nvme_latency_vlog_bpf.skel.h"
#include "nvme_strings.h"

/*
Program used to monitor NVMe request latency.
By monitoring the IO latency at the NVMe driver layer we can isolate problem
sources between the device and the rest of the storage stack layers.

Useful flags / settings:
* --ctrl_id=X. Monitor the latency only for the controller X.
* --lat_min_us=X. Sets the minimum latency to be considered for the histogram
  buckets. This allows to have more granularity around the specified value.
* --split_size. If set the histograms are split by size classes:
  <=16KiB, (16KiB,64KiB], >64KiB
* --lbs512. If set, the size classes are computed assuming 512 byte logical
  block size. By default 4KiB logical block size is assumed.

bazel build :nvme_latency && sudo bazel-bin/nvme_latency

# Example usage:
bazel build :nvme_latency && cp -f bazel-bin/nvme_latency /tmp/nvme_latency && \
sudo /tmp/nvme_latency --ctrl_id=0 --split_size --lat_min_us=65

# Home nvme3
bazel build :nvme_latency && cp -f bazel-bin/nvme_latency /tmp/nvme_latency && \
sudo /tmp/nvme_latency   --ctrl_id=3 --split_size --lat_min_us=65

# Home generate 300000 IO.
fio --name=read_lat_1 --thread=1   --ioengine=libaio --size=1200000K \
  --filesize=100% --direct=1 --randrepeat=0 --norandommap=1 \
  --filename=/dev/nvme3n1   --rw=randread --iodepth=1 --bs=4K

Improvement opportunities:
* Cleanup old entries in the in-flight command map.
https://docs.ebpf.io/linux/helper-function/bpf_timer_set_callback/
* Split each bucket to increase the number of buckets
* Print exclusive and total percentiles within the histogram
* Compute standard percentiles and print them
* Query the namespace block sizes and supply them to the BPF to filter sizes
correctly
* Print one percent lows and point one percent lows latency
* Add the ability to skip the latency measurements if the in-flight command
count or in-flight byte count exceeds a certain threshold
*/

ABSL_DECLARE_FLAG(int, stderrthreshold);

ABSL_FLAG(int, ctrl_id, -1,
          "NVMe controller ID to filter on, -1 for all controllers");
ABSL_FLAG(int, nsid, -1, "");

ABSL_FLAG(int, lat_min_us, -1,
          "The minimum histogram latency to be considered. Provides more "
          "granularity around this value.");
ABSL_FLAG(int, lat_shift, -1, "");

ABSL_FLAG(bool, split_size, false, "If set splits the histograms by size");

ABSL_FLAG(bool, trace, false,
          "If set will load a program that includes bpf_printk. Requires a "
          "kernel built with CONFIG_TRACING and CONFIG_BPF_EVENTS. To display "
          "the events cat /sys/kernel/debug/tracing/trace_pipe");

ABSL_FLAG(bool, lbs512, false, "");

static volatile bool exiting = false;
static void sig_handler(int sig) {
  exiting = true;
  std::cout << "Exiting on signal " << sig << std::endl;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  if (absl::GetFlag(FLAGS_stderrthreshold) == 0 || ABSL_VLOG_IS_ON(1)) {
    return vfprintf(stderr, format, args);
  }
  return 0;
}

// Latency histogram parameters.
nvme_bpf::Histogram g_lat_hist;

absl::Status PrintHist(const struct latency_hist& hist) {
  nvme_bpf::Histogram histogram = g_lat_hist;

  histogram.slots = hist.slots;
  histogram.total_count = hist.total_count;
  histogram.total_sum = hist.total_sum;
  return nvme_bpf::PrintHistogram(histogram);
}

template <typename T1, typename T2, typename T3>
struct TupleHash {
  size_t operator()(const std::tuple<T1, T2, T3>& t) const {
    // Combine hashes of individual elements
    return std::hash<T1>()(std::get<0>(t)) ^
           (std::hash<T2>()(std::get<1>(t)) << 1) ^
           (std::hash<T3>()(std::get<2>(t)) << 2);
  }
};

absl::Status PrintAllHists(struct bpf_map* hists) {
  int fd = bpf_map__fd(hists);
  if (fd < 0) {
    if (fd == -1) {
      std::cerr << "BPF latency histogram map not created. " << std::endl;
    } else {
      std::cerr << "BPF latency histogram map error. err=" << fd << std::endl;
    }
    return absl::InternalError("BPF map fd error");
  }

  struct latency_hist_key dummy_key;
  using TCtrlId = decltype(dummy_key.ctrl_id);
  using TOpcode = decltype(dummy_key.opcode);
  using TSizeClass = decltype(dummy_key.size_class);

  std::set<TCtrlId> controllers;
  std::set<TOpcode> opcodes;
  std::set<TSizeClass> sizes;
  std::unordered_set<std::tuple<TCtrlId, TOpcode, TSizeClass>,
                     TupleHash<TCtrlId, TOpcode, TSizeClass>>
      keys;

  {
    struct latency_hist_key lookup_key = {};
    lookup_key.ctrl_id = std::numeric_limits<TCtrlId>::max();
    lookup_key.opcode = 0;
    struct latency_hist_key next_key;

    if (bpf_map_get_next_key(fd, &lookup_key, &next_key) != 0) {
      std::cout << "No entries in histogram map." << std::endl;
      return absl::OkStatus();
    }

    // Scan the map and find all controllers / opcodes / sizes.
    while (0 == bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
      controllers.insert(next_key.ctrl_id);
      opcodes.insert(next_key.opcode);
      sizes.insert(next_key.size_class);

      keys.insert(std::make_tuple(next_key.ctrl_id, next_key.opcode,
                                  next_key.size_class));

      lookup_key = next_key;
    }
  }

  // Print the histograms in a meaningful order.
  for (const auto& ctrl_id : controllers) {
    for (const auto& opcode : opcodes) {
      for (const auto& size_class : sizes) {
        if (keys.find(std::make_tuple(ctrl_id, opcode, size_class)) ==
            keys.end()) {
          // Short circuit to avoid going through the BPF functions.
          continue;
        }

        struct latency_hist_key lookup_key = {};
        lookup_key.ctrl_id = ctrl_id;
        lookup_key.opcode = opcode;
        lookup_key.size_class = size_class;

        struct latency_hist hist;
        int err = bpf_map_lookup_elem(fd, &lookup_key, &hist);
        if (err < 0) {
          // Shouldn't really happen ...
          continue;
        }

        std::cout << "key: ctrl_id=" << ctrl_id
                  << ", opcode=" << static_cast<int>(opcode) << " "
                  << nvme_abi::NvmeIoOpcodeToString(
                         static_cast<nvme_abi::NvmeOpcode>(opcode));
        if (absl::GetFlag(FLAGS_split_size)) {
          if (size_class == 0) {
            std::cout << ", <=16KiB";
          } else if (size_class == 1) {
            std::cout << ", (16KiB, 64KiB]";
          } else {
            std::cout << ", (64KiB, inf)";
          }
        } else {
          LOG_IF_EVERY_N_SEC(ERROR, size_class != 0, 1)
              << "Unexpected size_class " << static_cast<int>(size_class)
              << " when --split_size is not set.";
        }
        std::cout << std::endl;

        auto ps = PrintHist(hist);
        if (!ps.ok()) {
          std::cerr << "Failed to print histogram: " << ps.message()
                    << std::endl;
          break;
        }
      }
    }
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

template <typename TSkel>
absl::Status RunMain() {
  // Set up libbpf errors and debug info callback.
  libbpf_set_print(libbpf_print_fn);

  // Handle SIGINT and SIGTERM to exit gracefully.
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  TSkel* skel;
  int err;

  skel = TSkel::open();
  if (skel == nullptr) {
    return absl::InternalError("Failed to open and load BPF skeleton");
  }
  auto skel_destroy_cleanup =
      absl::MakeCleanup([&skel]() { TSkel::destroy(skel); });

  // Initialize skel filters and parameters.
  auto filter_ctrl_id = absl::GetFlag(FLAGS_ctrl_id);
  if (filter_ctrl_id >= 0) {
    skel->rodata->filter_ctrl_id = filter_ctrl_id;
  }
  auto flag_lat_min_us = absl::GetFlag(FLAGS_lat_min_us);
  if (flag_lat_min_us >= 0) {
    skel->rodata->latency_min = flag_lat_min_us;
  }

  auto flag_lat_shift = absl::GetFlag(FLAGS_lat_shift);
  if (flag_lat_shift >= 0) {
    skel->rodata->latency_shift = flag_lat_shift;
  }

  auto flag_nsid = absl::GetFlag(FLAGS_nsid);
  if (flag_nsid >= 0) {
    skel->rodata->filter_nsid = flag_nsid;
  }

  auto flag_split_size = absl::GetFlag(FLAGS_split_size);
  if (flag_split_size) {
    if (absl::GetFlag(FLAGS_lbs512)) {
      skel->rodata->class1_size_nlb = 4 * 8;   // 16 KiB
      skel->rodata->class2_size_nlb = 16 * 8;  // 64 KiB
    } else {
      skel->rodata->class1_size_nlb = 4;   // 16 KiB
      skel->rodata->class2_size_nlb = 16;  // 64 KiB
    }
  }

  // Read global values, either set in the skel or overridden from flags above.
  g_lat_hist.lat_min_us = skel->rodata->latency_min;
  g_lat_hist.lat_shift = skel->rodata->latency_shift;
  g_lat_hist.max_slots = LATENCY_MAX_SLOTS;

  err = TSkel::load(skel);
  if (err) {
    return absl::InternalError(
        absl::StrCat("Failed to load and verify BPF skeleton, err=", err));
  }

  err = TSkel::attach(skel);
  if (err) {
    return absl::InternalError(
        absl::StrCat("Failed to attach BPF skeleton, err=", err));
  }
  auto skel_detach_cleanup =
      absl::MakeCleanup([&skel]() { TSkel::detach(skel); });

  std::cout << "Successfully started!" << std::endl;

  absl::Time next_print = absl::Now() + absl::Seconds(1);
  while (!exiting) {
    auto now = absl::Now();
    if (now > next_print) {
      std::cout << "=====================" << std::endl;
      PrintAllHists(skel->maps.hists).IgnoreError();
      next_print = now + absl::Seconds(1);
    }
    absl::SleepFor(absl::Milliseconds(50));
  }

  return absl::OkStatus();
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  absl::Status main_status;
  if (absl::GetFlag(FLAGS_trace)) {
    main_status = RunMain<nvme_latency_vlog_bpf>();
  } else {
    main_status = RunMain<nvme_latency_bpf>();
  }
  if (!main_status.ok()) {
    std::cerr << main_status;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
