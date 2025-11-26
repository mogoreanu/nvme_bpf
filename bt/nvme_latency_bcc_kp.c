// #include "vmlinux.h"
// #include <bpf/bpf_core_read.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>

#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/nvme.h>
#include <linux/nvme_ioctl.h>
#include <uapi/linux/ptrace.h>

static inline u16 nvme_req_qid(struct request* req) {
  if (!req->q->queuedata) return 0;

  return req->mq_hctx->queue_num + 1;
}

struct nvme_fault_inject {
#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
  struct fault_attr attr;
  struct dentry* parent;
  bool dont_retry; /* DNR, do not retry */
  u16 status;      /* status code */
#endif
};

// This struct is in `linux/drivers/nvme/host/nvme.h` which is, apparently, not
// available in BPF, copy it here for now.
struct nvme_ns {
  struct list_head list;

  struct nvme_ctrl* ctrl;
  struct request_queue* queue;
  struct gendisk* disk;
#ifdef CONFIG_NVME_MULTIPATH
  enum nvme_ana_state ana_state;
  u32 ana_grpid;
#endif
  struct list_head siblings;
  struct kref kref;
  struct nvme_ns_head* head;

  unsigned long flags;
#define NVME_NS_REMOVING 0
#define NVME_NS_ANA_PENDING 2
#define NVME_NS_FORCE_RO 3
#define NVME_NS_READY 4
#define NVME_NS_SYSFS_ATTR_LINK 5

  struct cdev cdev;
  struct device cdev_device;

  struct nvme_fault_inject fault_inject;
};

struct nvme_request {
  struct nvme_command* cmd;
  union nvme_result result;
  u8 genctr;
  u8 retries;
  u8 flags;
  u16 status;
#ifdef CONFIG_NVME_MULTIPATH
  unsigned long start_time;
#endif
  struct nvme_ctrl* ctrl;
};

enum nvme_ctrl_state {
  NVME_CTRL_NEW,
  NVME_CTRL_LIVE,
  NVME_CTRL_RESETTING,
  NVME_CTRL_CONNECTING,
  NVME_CTRL_DELETING,
  NVME_CTRL_DELETING_NOIO,
  NVME_CTRL_DEAD,
};

struct nvme_ctrl {
  bool comp_seen;
  bool identified;
  bool passthru_err_log_enabled;
  enum nvme_ctrl_state state;
  spinlock_t lock;
  struct mutex scan_lock;
  const struct nvme_ctrl_ops* ops;
  struct request_queue* admin_q;
  struct request_queue* connect_q;
  struct request_queue* fabrics_q;
  struct device* dev;
  int instance;
  int numa_node;
  struct blk_mq_tag_set* tagset;
  struct blk_mq_tag_set* admin_tagset;
  struct list_head namespaces;
  struct mutex namespaces_lock;
  struct srcu_struct srcu;
  struct device ctrl_device;
  struct device* device; /* char device */
#ifdef CONFIG_NVME_HWMON
  struct device* hwmon_device;
#endif
  struct cdev cdev;
  struct work_struct reset_work;
  struct work_struct delete_work;
  wait_queue_head_t state_wq;

  struct nvme_subsystem* subsys;
  struct list_head subsys_entry;

  struct opal_dev* opal_dev;

  u16 cntlid;

  u16 mtfa;
  u32 ctrl_config;
  u32 queue_count;

  u64 cap;
  u32 max_hw_sectors;
  u32 max_segments;
  u32 max_integrity_segments;
  u32 max_zeroes_sectors;
#ifdef CONFIG_BLK_DEV_ZONED
  u32 max_zone_append;
#endif
  u16 crdt[3];
  u16 oncs;
  u8 dmrl;
  u32 dmrsl;
  u16 oacs;
  u16 sqsize;
  u32 max_namespaces;
  atomic_t abort_limit;
  u8 vwc;
  u32 vs;
  u32 sgls;
  u16 kas;
  u8 npss;
  u8 apsta;
  u16 wctemp;
  u16 cctemp;
  u32 oaes;
  u32 aen_result;
  u32 ctratt;
  unsigned int shutdown_timeout;
  unsigned int kato;
  bool subsystem;
  unsigned long quirks;
  struct nvme_id_power_state psd[32];
  struct nvme_effects_log* effects;
  struct xarray cels;
  struct work_struct scan_work;
  struct work_struct async_event_work;
  struct delayed_work ka_work;
  struct delayed_work failfast_work;
  struct nvme_command ka_cmd;
  unsigned long ka_last_check_time;
  struct work_struct fw_act_work;
  unsigned long events;

#ifdef CONFIG_NVME_MULTIPATH
  /* asymmetric namespace access: */
  u8 anacap;
  u8 anatt;
  u32 anagrpmax;
  u32 nanagrpid;
  struct mutex ana_lock;
  struct nvme_ana_rsp_hdr* ana_log_buf;
  size_t ana_log_size;
  struct timer_list anatt_timer;
  struct work_struct ana_work;
  atomic_t nr_active;
#endif

#ifdef CONFIG_NVME_HOST_AUTH
  struct work_struct dhchap_auth_work;
  struct mutex dhchap_auth_mutex;
  struct nvme_dhchap_queue_context* dhchap_ctxs;
  struct nvme_dhchap_key* host_key;
  struct nvme_dhchap_key* ctrl_key;
  u16 transaction;
#endif
  key_serial_t tls_pskid;

  /* Power saving configuration */
  u64 ps_max_latency_us;
  bool apst_enabled;

  /* PCIe only: */
  u16 hmmaxd;
  u32 hmpre;
  u32 hmmin;
  u32 hmminds;

  /* Fabrics only */
  u32 ioccsz;
  u32 iorcsz;
  u16 icdoff;
  u16 maxcmd;
  int nr_reconnects;
  unsigned long flags;
  struct nvmf_ctrl_options* opts;

  struct page* discard_page;
  unsigned long discard_page_busy;

  struct nvme_fault_inject fault_inject;

  enum nvme_ctrl_type cntrltype;
  enum nvme_dctype dctype;
};

static inline struct nvme_request* nvme_req(struct request* req) {
  return blk_mq_rq_to_pdu(req);
}

#define VLOG false

#define LAT_HIST_SPLIT_SHIFT 0

BPF_HASH(in_flight_reqs, struct request*, u64, 4096);
BPF_HISTOGRAM(req_lat_hist_us, int, 64 * (1 << LAT_HIST_SPLIT_SHIFT));

int nvme_setup_cmd_return(struct pt_regs* ctx, struct nvme_ns* ns,
                          struct request* req) {
  // int ret = PT_REGS_RC(ctx)
  u16 qid = nvme_req_qid(req);
  struct nvme_request* nreq = nvme_req(req);
  struct nvme_command* nvme_cmd = nreq->cmd;
  int ctrl_id = nreq->ctrl->instance;
  if (VLOG) {
    bpf_trace_printk("nvme_setup_cmd qid: %d opcode: %x cid: %d\\n", qid,
                     nvme_cmd->common.opcode, nvme_cmd->common.command_id);
  }
  u64 nsec = bpf_ktime_get_ns();
  in_flight_reqs.update(&req, &nsec);

  return 0;
}

int nvme_complete_rq(struct pt_regs* ctx, struct request* req) {
  struct nvme_request* nreq = nvme_req(req);
  struct nvme_command* nvme_cmd = nreq->cmd;
  u64 nsec = bpf_ktime_get_ns();

  u64* start_nsec_ptr = in_flight_reqs.lookup(&req);
  if (start_nsec_ptr) {
    u64 delta = nsec - *start_nsec_ptr;
    req_lat_hist_us.increment(bpf_log2l(delta / 1000));
    in_flight_reqs.delete(&req);
  }
  if (VLOG) {
    bpf_trace_printk("nvme_complete_rq opcode: %x cid: %d\\n",
                     nvme_cmd->common.opcode, nvme_cmd->common.command_id);
  }

  return 0;
}