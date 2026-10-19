#include "nvme_latency/fake_latency_source.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <numbers>
#include <random>
#include <string>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/random/distributions.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "histogram.bpf.h"
#include "nvme_abi.h"

namespace nvme_bpf {
namespace {

constexpr uint8_t kFlush = static_cast<uint8_t>(nvme_abi::NvmeOpcode::kFlush);
constexpr uint8_t kWrite = static_cast<uint8_t>(nvme_abi::NvmeOpcode::kWrite);
constexpr uint8_t kRead = static_cast<uint8_t>(nvme_abi::NvmeOpcode::kRead);

// Traffic profile for one (controller, opcode).
struct Profile {
  uint32_t ctrl_id;
  uint8_t opcode;
  double peak_iops;
  double median_us;   // Median latency at low load.
  double sigma;       // Log-normal shape.
  double tail_prob;   // Probability of a slow (tail) request.
  double tail_mult;   // How much slower tail requests are.
  double period_s;    // Load variation period.
  double phase;       // Load variation phase, radians.
  double spike_every_s;
  double spike_len_s;
  double spike_mult;  // Latency multiplier during a spike.
};

constexpr Profile kProfiles[] = {
    {0, kRead, 42000, 82, 0.28, 0.004, 9, 90, 0.0, 47, 6, 3.0},
    {0, kWrite, 16000, 21, 0.45, 0.006, 22, 90, 1.3, 47, 6, 4.0},
    {0, kFlush, 35, 900, 0.50, 0.020, 5, 90, 2.0, 47, 6, 2.0},
    {1, kRead, 9000, 135, 0.35, 0.003, 7, 140, 0.7, 73, 4, 2.5},
    {1, kWrite, 3500, 38, 0.50, 0.004, 12, 140, 2.4, 73, 4, 3.0},
};

// Size class mix used with --split_size: (probability, latency multiplier).
constexpr std::pair<double, double> kSizeClasses[] = {
    {0.70, 1.0}, {0.20, 1.7}, {0.10, 3.5}};

constexpr int64_t kMaxRequestsPerRead = 2'000'000;

class FakeLatencySource : public LatencySource {
 public:
  explicit FakeLatencySource(const FakeSourceOptions& options)
      : options_(options),
        gen_(options.seed),
        start_(options.now()),
        last_(start_) {
    info_.source = "fake";
    info_.params = options.params;
    info_.start_time = start_;
    info_.interval = options.interval;
    info_.split_size = options.split_size;
    info_.ctrl_id_filter = options.ctrl_id_filter;
  }

  std::string name() const override { return "fake"; }

  absl::StatusOr<Snapshot> Read() override {
    const absl::Time now = options_.now();
    const double dt =
        std::clamp(absl::ToDoubleSeconds(now - last_), 0.0, 10.0);
    // Evaluate the load at the middle of the elapsed interval.
    const double t = absl::ToDoubleSeconds(last_ - start_) + dt / 2;
    for (const Profile& p : kProfiles) {
      if (options_.ctrl_id_filter >= 0 &&
          p.ctrl_id != static_cast<uint32_t>(options_.ctrl_id_filter)) {
        continue;
      }
      Simulate(p, t, dt);
    }
    last_ = now;

    Snapshot snapshot;
    snapshot.time = now;
    snapshot.info = info_;
    snapshot.hists.assign(hists_.begin(), hists_.end());
    return snapshot;
  }

 private:
  void Simulate(const Profile& p, double t, double dt) {
    const double wave =
        0.5 + 0.5 * std::sin(2 * std::numbers::pi * t / p.period_s + p.phase);
    const double load = 0.55 + 0.45 * wave;  // Fraction of the peak load.
    const bool spike =
        std::fmod(t + p.phase * 7, p.spike_every_s) < p.spike_len_s;
    const double iops = p.peak_iops * load * (spike ? 0.6 : 1.0);
    // Latency grows quickly as the device approaches its peak load.
    const double median = p.median_us * (1.0 + 0.8 * std::pow(load, 4)) *
                          (spike ? p.spike_mult : 1.0);
    const double tail_prob = std::min(1.0, p.tail_prob * (spike ? 5 : 1));

    const int64_t n = std::min<int64_t>(
        kMaxRequestsPerRead, absl::Poisson<int64_t>(gen_, iops * dt));
    const bool sized =
        options_.split_size && (p.opcode == kRead || p.opcode == kWrite);
    for (int64_t i = 0; i < n; ++i) {
      uint8_t size_class = 0;
      double size_mult = 1.0;
      if (sized) {
        double u = absl::Uniform(gen_, 0.0, 1.0);
        for (uint8_t c = 0; c < std::size(kSizeClasses); ++c) {
          size_class = c;
          size_mult = kSizeClasses[c].second;
          u -= kSizeClasses[c].first;
          if (u < 0) break;
        }
      }
      double latency_us = std::exp(
          absl::Gaussian(gen_, std::log(median * size_mult), p.sigma));
      if (absl::Bernoulli(gen_, tail_prob)) {
        latency_us *= p.tail_mult * (1.0 + absl::Exponential(gen_, 1.0));
      }
      Record(HistKey{p.ctrl_id, p.opcode, size_class}, latency_us);
    }
  }

  void Record(const HistKey& key, double latency_us) {
    CumulativeHist& hist = hists_[key];
    const HistogramParams& params = options_.params;
    const auto v = static_cast<uint64_t>(std::llround(std::max(0.0, latency_us)));
    ++hist.total_count;
    hist.total_sum_us += v;
    const int slot =
        bpf_get_bucket(v, params.lat_min_us, params.lat_shift, params.max_slots);
    if (slot >= 0) ++hist.slots[slot];
  }

  const FakeSourceOptions options_;
  SourceInfo info_;
  std::mt19937_64 gen_;
  const absl::Time start_;
  absl::Time last_;
  absl::btree_map<HistKey, CumulativeHist> hists_;
};

}  // namespace

std::unique_ptr<LatencySource> CreateFakeLatencySource(
    const FakeSourceOptions& options) {
  return std::make_unique<FakeLatencySource>(options);
}

}  // namespace nvme_bpf
