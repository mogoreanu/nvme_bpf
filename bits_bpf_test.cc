
#include <iostream>
#include <ostream>
#include <string>

#include "absl/log/log.h"
#include "bits.bpf.h"
#include "gtest/gtest.h"

/*
bazel test --test_output=streamed :bits_bpf_test
 */

namespace {

TEST(Log2, ValueToBucket) {
  ASSERT_EQ(bpf_log2(0), 0);
  ASSERT_EQ(bpf_log2(1), 0);

  ASSERT_EQ(bpf_log2(2), 1);
  ASSERT_EQ(bpf_log2(3), 1);

  ASSERT_EQ(bpf_log2(4), 2);
  ASSERT_EQ(bpf_log2(5), 2);
  ASSERT_EQ(bpf_log2(7), 2);

  ASSERT_EQ(bpf_log2(8), 3);
  ASSERT_EQ(bpf_log2(9), 3);
  ASSERT_EQ(bpf_log2(15), 3);

  ASSERT_EQ(bpf_log2(16), 4);
}

TEST(BpfHistogram, ValueToBucket) {
  //                               v < min                   => returns max_slots
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

}  // namespace
