#include <bitset>
#include <cstdint>
#include <ostream>
#include <random>

#include "absl/log/log.h"
#include "absl/random/random.h"
#include "benchmark/benchmark.h"
#include "histogram.bpf.h"
#include "gtest/gtest.h"

/*
sudo cpufreq-set -g performance

bazel build -c opt  --dynamic_mode=off :histogram_benchmarks \
&& taskset -c 0 bazel-bin/histogram_benchmarks \
  --benchmark_filter=all \
  --benchmark_repetitions=1 \
  --benchmark_enable_random_interleaving=false

sudo cpufreq-set -g powersave

Running bazel-bin/histogram_benchmarks
Run on (72 X 3700 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x36)
  L1 Instruction 32 KiB (x36)
  L2 Unified 1024 KiB (x36)
  L3 Unified 25344 KiB (x2)
Load Average: 5.10, 5.31, 5.32
-------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations
-------------------------------------------------------------------
BM_HistogramBaseline           18.7 ns         18.7 ns     37263693
BM_HistogramBpfClzll           28.9 ns         28.9 ns     24279760
BM_HistogramBuiltinClzll       19.3 ns         19.3 ns     36380711
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
