
#include <iostream>
#include <ostream>
#include <random>
#include <string>

#include "absl/log/log.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "bits.bpf.h"
#include "gtest/gtest.h"

/*
bazel test --test_output=streamed :bits_bpf_test
 */

namespace {

TEST(Log2, ValueToBucket) {
  ASSERT_EQ(bpf_log2(0), 0ULL);
  ASSERT_EQ(bpf_log2(1), 0ULL);

  ASSERT_EQ(bpf_log2(2), 1ULL);
  ASSERT_EQ(bpf_log2(3), 1ULL);

  ASSERT_EQ(bpf_log2(4), 2ULL);
  ASSERT_EQ(bpf_log2(5), 2ULL);
  ASSERT_EQ(bpf_log2(7), 2ULL);

  ASSERT_EQ(bpf_log2(8), 3ULL);
  ASSERT_EQ(bpf_log2(9), 3ULL);
  ASSERT_EQ(bpf_log2(15), 3ULL);

  ASSERT_EQ(bpf_log2(16), 4ULL);
}

TEST(Log2, BucketToValue) {
  ASSERT_EQ(bpf_log_bucket_low(0), 0ULL);
  ASSERT_EQ(bpf_log_bucket_high(0), 1ULL);

  ASSERT_EQ(bpf_log_bucket_low(1), 2ULL);
  ASSERT_EQ(bpf_log_bucket_high(1), 3ULL);

  ASSERT_EQ(bpf_log_bucket_low(2), 4ULL);
  ASSERT_EQ(bpf_log_bucket_high(2), 7ULL);

  ASSERT_EQ(bpf_log_bucket_low(3), 8ULL);
  ASSERT_EQ(bpf_log_bucket_high(3), 15ULL);
}

}  // namespace
