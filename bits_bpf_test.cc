
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

TEST(Log2, BucketToValue) {
  ASSERT_EQ(bpf_bucket_low(0), 0);
  ASSERT_EQ(bpf_bucket_high(0), 1);

  ASSERT_EQ(bpf_bucket_low(1), 2);
  ASSERT_EQ(bpf_bucket_high(1), 3);

  ASSERT_EQ(bpf_bucket_low(2), 4);
  ASSERT_EQ(bpf_bucket_high(2), 7);

    ASSERT_EQ(bpf_bucket_low(3), 8);
  ASSERT_EQ(bpf_bucket_high(3), 15);
}

}  // namespace
