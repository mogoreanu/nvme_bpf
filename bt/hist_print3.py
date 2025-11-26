import math

def pretty_print_log_hist(hist_data, has_zero_bucket=False, starting_power=0, bar_scale=100):
    """
    Pretty prints a logarithmic histogram where each power-of-2
    range is split into 4 consecutive buckets.

    This function does NOT collapse any buckets and handles integer-only
    ranges as per specific rules for [1, 2) and [2, 4).
    It skips printing any buckets marked as "[Invalid]".

    Args:
        hist_data (list or tuple): A list of counts.
        has_zero_bucket (bool): If True, assumes hist_data[0] is for the
                                range [0, 1) and the 4-split logic
                                starts from hist_data[1].
        starting_power (int): The 'n' in 2^n for the *first* 4-bucket
                              range. Defaults to 0 (i.e., [1, 2)).
                              If has_zero_bucket is True, this applies
                              to the range starting at hist_data[1].
                              Using negative values may result in
                              '[Invalid (float)]' buckets.
        bar_scale (int): A scaling factor to determine the max length
                         of the asterisk bar.
    """
    
    total_samples = sum(hist_data)
    if total_samples == 0:
        print("Histogram is empty.")
        return

    print(f"Total Samples: {total_samples}\n")
    
    # Find the maximum percentage for scaling the bar
    max_percent = 0
    if total_samples > 0:
        max_percent = max((count / total_samples) * 100 for count in hist_data)

    # Determine the scaling factor for the asterisk bar
    scale_factor = 0
    if max_percent > 0:
        scale_factor = bar_scale / max_percent

    ranges = []
    max_range_str_len = 0
    
    # First pass: Calculate all range strings to find max width
    for i in range(len(hist_data)):
        range_str = ""
        if has_zero_bucket and i == 0:
            range_str = "[0, 1)"
        else:
            # Adjust index 'i' if we had a special zero bucket
            adj_i = i
            if has_zero_bucket:
                adj_i = i - 1
                
            # Check for negative index just in case
            if adj_i < 0:
                range_str = "[INVALID BUCKET]"
            else:
                # Which power of 2 are we in?
                # adj_i = 0,1,2,3 -> power_index = 0
                # adj_i = 4,5,6,7 -> power_index = 1
                power_index = adj_i // 4
                sub_index = adj_i % 4
                
                # This is the 'n' in 2^n
                current_power_val = starting_power + power_index
                
                if current_power_val == 0: # Range [1, 2), n=0
                    if sub_index == 0:
                        range_str = "[1, 2)"
                    else:
                        range_str = "[Invalid]"
                
                elif current_power_val == 1: # Range [2, 4), n=1
                    if sub_index == 0:
                        range_str = "[2, 3)"
                    elif sub_index == 2:
                        range_str = "[3, 4)"
                    else:
                        range_str = "[Invalid]"
                        
                elif current_power_val < 0: # Ranges < 1
                    # Per user request, no floating point ranges
                    range_str = "[Invalid (float)]"
                    
                else: # n >= 2 (e.g., [4, 8), [8, 16), etc.)
                    range_start = 2**current_power_val
                    range_end = 2**(current_power_val + 1)
                    total_range_size = range_end - range_start
                    
                    # step_size will be an integer (1, 2, 4, ...)
                    step_size_int = total_range_size // 4
                    
                    bucket_start = range_start + (sub_index * step_size_int)
                    bucket_end = range_start + ((sub_index + 1) * step_size_int)
                    
                    range_str = f"[{bucket_start}, {bucket_end})"
             
        ranges.append(range_str)
        # We still need to find the max length of *valid* ranges
        if "invalid" not in range_str.lower():
            if len(range_str) > max_range_str_len:
                max_range_str_len = len(range_str)
            
    # Second pass: Print the formatted output
    for i, count in enumerate(hist_data):
        range_str = ranges[i]
        
        # Skip printing if the bucket is invalid
        if "invalid" in range_str.lower():
            continue
            
        percent = 0
        if total_samples > 0:
            percent = (count / total_samples) * 100
        
        # Create the asterisk bar
        bar_length = int(percent * scale_factor)
        bar = "*" * bar_length
        
        # Format the line
        # {range_str:<{max_range_str_len}} - Left-aligns the range string
        # {percent:8.2f}% - Formats percent to 2 decimal places, 8 chars wide
        print(f"{range_str:<{max_range_str_len}} | {percent:8.2f}% | {bar}")


# --- Example Usage ---
if __name__ == "__main__":
    
    # This example assumes the histogram data starts at n=0 (the [1, 2) range)
    # and does NOT have a special [0, 1) bucket.
    
    # hist[0]   = [1, 2)
    # hist[1]   = [Invalid]
    # hist[2]   = [Invalid]
    # hist[3]   = [Invalid]
    # hist[4]   = [2, 3)
    # hist[5]   = [Invalid]
    # hist[6]   = [3, 4)
    # hist[7]   = [Invalid]
    # hist[8-11]  = [4, 8) <-- First "normal" split
    # ...
    # hist[32-35] = [256, 512)
    
    example_hist_1 = [
        5, 0, 0, 0, # [1, 2) range (only first bucket is valid)
        15, 0, 20, 0, # [2, 4) range (buckets 0 and 2 are valid)
        15, 20, 22, 18, # [4, 8)
        30, 40, 35, 32, # [8, 16)
        50, 65, 80, 70, # [16, 32)
        100, 120, 110, 90, # [32, 64)
        150, 200, 180, 160, # [64, 128)
        300, 250, 220, 200, # [128, 256)
        1000, 800, 600, 400, # [256, 512)
        200, 100, 50, 25 # [512, 1024)
    ]

    print("--- Example 1: No [0, 1) bucket, starting_power=0 (i.e., [1, 2)) ---")
    # We set has_zero_bucket=False and starting_power=0
    # Note how buckets for [1, 2) and [2, 4) are now "Invalid"
    pretty_print_log_hist(example_hist_1, has_zero_bucket=False, starting_power=0, bar_scale=60)
    
    print("\n" + "="*80 + "\n")
    
    # This example assumes hist[0] is [0, 1) and the 4-split logic
    # starts at hist[1] with n=0 (the [1, 2) range).
    
    example_hist_2 = [
        500, # [0, 1)
        5, 0, 0, 0, # [1, 2) range
        15, 0, 20, 0, # [2, 4) range
        15, 20, 22, 18, # [4, 8)
        # ... and so on
    ]
    
    print("--- Example 2: With [0, 1) bucket, starting_power=0 (i.e., [1, 2)) ---")
    # We set has_zero_bucket=True
    pretty_print_log_hist(example_hist_2, has_zero_bucket=True, starting_power=0, bar_scale=60)

