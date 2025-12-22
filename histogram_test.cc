
#include <iostream>
#include <ostream>
#include <random>
#include <string>

#include "absl/log/log.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gtest/gtest.h"
#include "histogram.bpf.h"

/*
bazel test --test_output=streamed :histogram_test
 */

namespace {

TEST(BpfHistogram, ValueToBucket) {
  //                               v < min                   => returns
  //                               max_slots
  // v >= min                   && v < min + 2 ^ shift       => returns 0
  // v >= min + 2 ^ shift       && v < min + 2 ^ (shift + 1) => returns 1
  // v >= min + 2 ^ (shift + 1) && v < min + 2 ^ (shift + 2) => returns 2
  ASSERT_EQ(bpf_get_bucket(0, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_get_bucket(1, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 1);
  ASSERT_EQ(bpf_get_bucket(2, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(3, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(4, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(5, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(7, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(8, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 4);

  ASSERT_EQ(bpf_get_bucket(9, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 13);
  ASSERT_EQ(bpf_get_bucket(10, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_get_bucket(11, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 1);
  ASSERT_EQ(bpf_get_bucket(12, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(13, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(14, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(15, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(17, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(18, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 4);

  // With shift=2
  ASSERT_EQ(bpf_get_bucket(9, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 13);
  ASSERT_EQ(bpf_get_bucket(10, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_get_bucket(11, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_get_bucket(13, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 0);

  ASSERT_EQ(bpf_get_bucket(14, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 1);
  ASSERT_EQ(bpf_get_bucket(15, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 1);
  ASSERT_EQ(bpf_get_bucket(17, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 1);

  ASSERT_EQ(bpf_get_bucket(18, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(23, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(24, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_get_bucket(25, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 2);

  ASSERT_EQ(bpf_get_bucket(26, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(27, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 3);
  ASSERT_EQ(bpf_get_bucket(41, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 3);

  ASSERT_EQ(bpf_get_bucket(42, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 4);

  ASSERT_EQ(
      bpf_get_bucket(10 + (1 << 15), /*min=*/10, /*shift=*/2, /*max_slots=*/13),
      -1);
}

TEST(BpfHistogram, BucketToValue) {
  //                               v < min                   => returns 0
  // v >= min                   && v < min + 2 ^ shift       => returns 64
  // v >= min + 2 ^ shift       && v < min + 2 ^ (shift + 1) => returns 63
  // v >= min + 2 ^ (shift + 1) && v < min + 2 ^ (shift + 2) => returns 62
  ASSERT_EQ(bpf_bucket_low(0, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_bucket_high(0, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 1);

  ASSERT_EQ(bpf_bucket_low(1, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 1);
  ASSERT_EQ(bpf_bucket_high(1, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 2);

  ASSERT_EQ(bpf_bucket_low(2, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 2);
  ASSERT_EQ(bpf_bucket_high(2, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 4);

  ASSERT_EQ(bpf_bucket_low(3, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 4);
  ASSERT_EQ(bpf_bucket_high(3, /*min=*/0, /*shift=*/0, /*max_slots=*/13), 8);

  // Min = 10
  ASSERT_EQ(bpf_bucket_low(13, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_bucket_high(13, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 10);

  ASSERT_EQ(bpf_bucket_low(0, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 10);
  ASSERT_EQ(bpf_bucket_high(0, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 11);

  ASSERT_EQ(bpf_bucket_low(1, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 11);
  ASSERT_EQ(bpf_bucket_high(1, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 12);

  ASSERT_EQ(bpf_bucket_low(2, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 12);
  ASSERT_EQ(bpf_bucket_high(2, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 14);

  ASSERT_EQ(bpf_bucket_low(3, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 14);
  ASSERT_EQ(bpf_bucket_high(3, /*min=*/10, /*shift=*/0, /*max_slots=*/13), 18);

  // Min = 10, shift=2
  ASSERT_EQ(bpf_bucket_low(13, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 0);
  ASSERT_EQ(bpf_bucket_high(13, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 10);

  ASSERT_EQ(bpf_bucket_low(0, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 10);
  ASSERT_EQ(bpf_bucket_high(0, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 14);

  ASSERT_EQ(bpf_bucket_low(1, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 14);
  ASSERT_EQ(bpf_bucket_high(1, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 18);

  ASSERT_EQ(bpf_bucket_low(2, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 18);
  ASSERT_EQ(bpf_bucket_high(2, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 26);

  ASSERT_EQ(bpf_bucket_low(3, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 26);
  ASSERT_EQ(bpf_bucket_high(3, /*min=*/10, /*shift=*/2, /*max_slots=*/13), 42);
}

TEST(Log2, BucketToValue) {
  ASSERT_EQ(bpf_log_bucket_low(0), 0);
  ASSERT_EQ(bpf_log_bucket_high(0), 1);

  ASSERT_EQ(bpf_log_bucket_low(1), 2);
  ASSERT_EQ(bpf_log_bucket_high(1), 3);

  ASSERT_EQ(bpf_log_bucket_low(2), 4);
  ASSERT_EQ(bpf_log_bucket_high(2), 7);

  ASSERT_EQ(bpf_log_bucket_low(3), 8);
  ASSERT_EQ(bpf_log_bucket_high(3), 15);
}

TEST(Log2, HistogramHelperTest) {
  int64_t lat_min_us = 10;
  int lat_shift = 2;
  int max_slots = 13;

  std::random_device rd;
  std::mt19937 gen(rd());

  int64_t max_histogram_value = lat_min_us + (1 << (lat_shift + max_slots - 1));
  std::uniform_int_distribution<uint64_t> d(0, max_histogram_value + 1000);

  absl::Time end = absl::Now() + absl::Seconds(1);
  int count = 1000;
  do {
    if (count == 0) {
      count = 1;
    }
    uint64_t x = d(gen);
    int b = bpf_get_bucket(x, lat_min_us, lat_shift, max_slots);

    if (b == -1) {
      ASSERT_GE(x, max_histogram_value)
          << "x=" << x << " b=" << b << " lat_min_us=" << lat_min_us
          << " lat_shift=" << lat_shift << " max_slots=" << max_slots;
    } else if (b == max_slots) {
      ASSERT_LT(x, lat_min_us)
          << "x=" << x << " b=" << b << " lat_min_us=" << lat_min_us
          << " lat_shift=" << lat_shift << " max_slots=" << max_slots;
    } else {
      uint64_t low = bpf_bucket_low(b, lat_min_us, lat_shift, max_slots);
      uint64_t high = bpf_bucket_high(b, lat_min_us, lat_shift, max_slots);
      ASSERT_LE(low, x) << "x=" << x << " b=" << b << " blow=" << low
                        << " bhigh=" << high << " lat_min_us=" << lat_min_us
                        << " lat_shift=" << lat_shift
                        << " max_slots=" << max_slots;
      ASSERT_LT(x, high) << "x=" << x << " b=" << b << " blow=" << low
                         << " bhigh=" << high << " lat_min_us=" << lat_min_us
                         << " lat_shift=" << lat_shift
                         << " max_slots=" << max_slots;
    }

    ASSERT_EQ(bpf_log_bucket_low(0), 0);
    ASSERT_EQ(bpf_log_bucket_high(0), 1);

  } while (absl::Now() < end || --count > 0);
}

}  // namespace
