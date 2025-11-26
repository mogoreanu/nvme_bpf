#ifndef NVME_LATENCY_H_
#define NVME_LATENCY_H_

typedef short unsigned int u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define LATENCY_MAX_SLOTS 27

struct request_key {
    int ctrl_id;
    int qid;
    u16 cid;
};

struct request_data {
    u64 start_ns;
};

struct latency_hist_key {
	u32 ctrl_id;
	u32 opcode;
};

struct latency_hist {
	u64 slots[LATENCY_MAX_SLOTS];
};


#endif  // NVME_LATENCY_H_