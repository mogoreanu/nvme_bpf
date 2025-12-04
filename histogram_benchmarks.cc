#include <bitset>
#include <cstdint>
#include <ostream>
#include <random>

#include "absl/log/log.h"
#include "absl/random/random.h"
#include "benchmark/benchmark.h"
#include "bits.bpf.h"
#include "gtest/gtest.h"

/*
sudo cpufreq-set -g performance

bazel build -c opt  --dynamic_mode=off :histogram_benchmarks \
&& taskset -c 0 bazel-bin/histogram_benchmarks \
  --benchmark_filter=all \
  --benchmark_repetitions=1 \
  --benchmark_enable_random_interleaving=false

sudo cpufreq-set -g powersave

-------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations
-------------------------------------------------------------------
BM_HistogramBaseline           15.2 ns         15.2 ns     46333995
BM_HistogramBpfClzll           25.2 ns         25.2 ns     28842895
BM_HistogramBuiltinClzll       16.2 ns         16.2 ns     41623624
*/

namespace mogo {

void BM_HistogramBaseline(benchmark::State& state) {
  uint64_t sum = 0;

  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint64_t> d(
      0, std::numeric_limits<uint64_t>::max());

  for (auto s : state) {
    uint64_t x = d(gen);
    benchmark::DoNotOptimize(x);
    sum += x;
  }
  VLOG(2) << sum;
}
BENCHMARK(BM_HistogramBaseline);

void BM_HistogramBpfClzll(benchmark::State& state) {
  uint64_t sum = 0;

  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint64_t> d(
      0, std::numeric_limits<uint64_t>::max());

  for (auto s : state) {
    uint64_t x = d(gen);
    benchmark::DoNotOptimize(x);

    sum += bpf_clzll(x);

    sum += x;
  }
  VLOG(2) << sum;
}
BENCHMARK(BM_HistogramBpfClzll);

void BM_HistogramBuiltinClzll(benchmark::State& state) {
  uint64_t sum = 0;

  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint64_t> d(
      0, std::numeric_limits<uint64_t>::max());

  for (auto s : state) {
    uint64_t x = d(gen);
    benchmark::DoNotOptimize(x);

    sum += __builtin_clzll(x);

    sum += x;
  }
  VLOG(2) << sum;
}
BENCHMARK(BM_HistogramBuiltinClzll);

}  // namespace mogo
