#ifndef NVME_ABI_H_
#define NVME_ABI_H_

#include <cstdint>
#include <cstring>

// The definitions in this header file match the latest version of the NVM
// Express Base Specification, available for download from
// https://nvmexpress.org/. NVM Express is usually abbreviated as NVMe. Later
// versions of the NVMe specification are backwards compatible with older
// versions of the NVMe specification.

namespace nvme_abi {

inline int nvme_abi_memcmp(const void* s1, const void* s2, size_t n) {
  return std::memcmp(s1, s2, n);
}

//////////////////////////
// Common structures
// This includes:
//  - DWORD (used in the Admin and I/O command set)
//  - Namespace identifier
//  - Metadata Pointer (not used by all commands)
//  - PRP Entry 1 and 2 (not used by all all commands)
//  - SGL Entry 1 and Metadata (shared by I/O command set)

constexpr uint16_t kSubmissionQueueEntrySizeBytes = 64;
constexpr uint16_t kCompletionQueueEntrySizeBytes = 16;
const uint16_t kIdentifySize = 4096;
constexpr uint16_t kSmartHealthLogPageSize = 512;
constexpr uint16_t kFirmwareSlotLogPageSize = 512;
// NVMe 1.4 spec section 3.1, base offset of Bar0 doorbell registers.
constexpr uint64_t kBar0DoorbellBaseOffset = 0x1000;
// The maximum number of namespace IDs returned by GetLogPage Changed Namespace
// List. Specified in go/nvme-1.3d Section 5.14.1.4.
constexpr uint16_t kChangedNamespaceListMaxSize = 1024;
// NSID FFFFFFFFh is a broadcast value that is used to specify all namespaces;
// NVMe spec 1.3d, section 6.1.2 "Valid and Invalid NSIDs".
constexpr uint32_t kBroadcastNsId = 0xFFFFFFFF;
// NVMe 1.4e spec section 5.15.2.2, figure 251, WCTEMP (bytes 266-267)
constexpr uint16_t kRecommendedWarningTemperature = 0x157;
// Maximum size of the SUBNQN string, per NVMe spec 1.2.1 section 7.9. SUBNQN
// must be a UTF-8 encoded and null-terminated.
constexpr uint16_t kMaxSubnqnSize = 223;

// Used to create a complex command by fusing two simpler commands together.
enum class FusedMode : uint8_t {
  // A normal operation (not fused).
  kNormal = 0,
  // Fused operation, first operation.
  kFirstOp = 1,
  // Fused operation, second operation.
  kSecondOp = 2,
  kReserved = 3,
};

// All possible opcodes NVMe commands.
enum class NvmeOpcode : uint8_t {
  // IO operation codes:
  kFlush = 0x00,                //
  kWrite = 0x01,                //
  kRead = 0x02,                 //
  kWriteUncorrectable = 0x04,   //
  kCompare = 0x005,             //
  kWriteZeros = 0x08,           // NVMe 1.1
  kDatasetMgmt = 0x09,          //
  kVerify = 0x0C,               // NVMe 1.4
  kReservationRegister = 0x0D,  // NVMe 1.1
  kReservationReport = 0x0E,    // NVMe 1.1
  kReservationAcquire = 0x11,   // NVMe 1.1
  kReservationRelease = 0x15,   // NVMe 1.1

  // Admin operation codes:
  kDeleteSubQueue = 0x00,            //
  kCreateSubQueue = 0x01,            //
  kGetLogPage = 0x02,                //
  kDeleteCompQueue = 0x04,           //
  kCreateCompQueue = 0x05,           //
  kIdentify = 0x06,                  //
  kAbort = 0x08,                     //
  kSetFeatures = 0x09,               //
  kGetFeatures = 0x0A,               //
  kAsyncEventReq = 0x0C,             //
  kNamespaceManagement = 0xD,        // NVMe 1.2
  kFirmwareActivate = 0x10,          //
  kFirmwareImgDownload = 0x11,       //
  kDeviceSelfTest = 0x14,            // NVMe 1.3
  kNamespaceAttachment = 0x15,       // NVMe 1.2
  kKeepAlive = 0x18,                 // NVMe 1.2.1
  kDirectiveSend = 0x19,             // NVMe 1.3
  kDirectiveReceive = 0x1A,          // NVMe 1.3
  kVirtualizationManagement = 0x1C,  // NVMe 1.3
  kNVMeMISend = 0x1D,                // NVMe 1.3
  kNVMeMIReceive = 0x1E,             // NVMe 1.3
  kDoorbellMemory = 0x7C,            // NVMe 1.3, aka Doorbell Buffer Config
  kFormatNVM = 0x80,                 //
  kSecurityRead = 0x81,              //
  kSecurityWrite = 0x82,             //
  kSanitize = 0x84,                  // NVMe 1.3
  kGetLbaStatus = 0x86,              // NVMe 1.4

  // Everything else is optional or undefined.
};

// Note: We could merge next two enums into single uint16_t enum that would be
// more correct/consistent, but that would make it hard to compare the values
// with the spec.

// Type of the status code. Directly coupled with StatusCode.
enum class StatusCodeType : uint8_t {
  kGeneric = 0,
  kCommandSpecific = 1,
  kMediaError = 2,
  kPathRelated = 3,
};

enum class StatusCode : uint8_t {
  // Generic status codes:
  kSuccess = 0x0,
  kInvalidOpcode = 0x1,
  kInvalidField = 0x2,
  kCommandIdConflict = 0x3,
  kDataTransferError = 0x4,
  kAbortedPowerLoss = 0x5,
  kInternalError = 0x6,
  kAbortedByRequest = 0x7,
  kAbortedSqDeletion = 0x8,
  // Command Aborted due to Failed Fused Command: The command was aborted due to
  // the other command in a fused operation failing.
  kAbortedFailedFused = 0x9,
  // Command Aborted due to Missing Fused Command: The fused command was aborted
  // due to the adjacent submission queue entry not containing a fused command
  // that is the other command in a supported fused operation.
  kAbortedMissingFused = 0xA,
  kInvalidNamespace = 0xB,
  kCommandSeqError = 0xC,
  kInvalidSglDesc = 0xD,
  kInvalidNumOfSglDesc = 0xE,
  kInvalidSglDataLength = 0xF,
  kInvalidSglMetadataLength = 0x10,
  kInvalidSglDescType = 0x11,
  kInvalidUseCtrlMemBuff = 0x12,
  kInvalidPrpOffset = 0x13,
  kAtomicWriteUnitExceeded = 0x14,
  kOpDenied = 0x15,
  kInvalidSglOffset = 0x16,
  kHostIdInconsistentFormat = 0x18,
  kKeepAliveTimerExpired = 0x19,
  kInvalidKeepAliveTimeout = 0x1A,
  kAbortedDuePreemptAbort = 0x1B,
  kSanitizeFailed = 0x1C,
  kSanitizeInProgress = 0x1D,
  kInvalidSglDataBlckGranularity = 0x1E,
  kNotSupportedForQueueInCMB = 0x1F,
  kNamespaceIsWriteProtected = 0x20,
  kCommandInterrupted = 0x21,
  kTransientTransportError = 0x22,
  // Generic status, NVM command set:
  kLbaOutOfRange = 0x80,
  kCapacity_exceeded = 0x81,
  kNamespaceNotReady = 0x82,
  kReservationConflict = 0x83,
  kFormatInProgress = 0x84,

  // Command specific:
  kCompletionQueueInvalid = 0x00,
  kInvalidQueueId = 0x01,
  kInvalidQueueSize = 0x02,
  kAbortCommandLimitExceeded = 0x03,
  kAsyncEventRequestLimitExceeded = 0x05,
  kInvalidFirmwareSlot = 0x06,
  kInvalidFirmwareImage = 0x07,
  kInvalidInterruptVector = 0x08,
  kInvalidLogPage = 0x09,
  kInvalidFormat = 0x0A,
  kFwActivationReqConventionalReset = 0x0B,
  kInvalidQueueDeletion = 0x0C,
  kFeatureIdentifierNotSaveable = 0x0D,
  kFeatureNotChangeable = 0x0E,
  kFeatureNotNamespaceSpecific = 0x0F,
  kFwActivationReqNVMReset = 0x10,
  kFwActivationReqCtrlLevelReset = 0x11,
  kFwActivationReqMaxTimeViolation = 0x12,
  kFwActivationProhibited = 0x13,
  kOverlappingRangeFirmwareCommit = 0x14,
  kNsInsufficientCapacity = 0x15,
  kNsIdentifierUnavailable = 0x16,
  kNsAlreadyAttached = 0x18,
  kNsIsPrivate = 0x19,
  kNsNotAttached = 0x1A,
  kThinProvisioningNotSupported = 0x1B,
  kControllerListInvalid = 0x1C,
  kDeviceSelfTestInProgress = 0x1D,
  kBootPartitionWriteProhibited = 0x1E,
  kInvalidControllerIdentifier = 0x1F,
  kInvalidSecondaryControllerState = 0x20,
  kInvalidNumCtrlResources = 0x21,
  kInvalidResourceIdentifier = 0x22,
  kSanitizeProhibitedWithPMR = 0x23,
  kANAGroupIdentifierInvalid = 0x24,
  kANAAttachFailed = 0x25,
  kInvalidControllerDataQueue = 0x37,
  kControllerNotSuspended = 0x3a,
  // Command specific, NVM command set:
  kConflictingAttributes = 0x80,
  kInvalidProtectionInformation = 0x81,
  kAttemptedWriteToReadOnlyRange = 0x82,

  // Media error, NVM command set:
  kWriteFault = 0x80,
  kUnrecoveredReadError = 0x81,
  kE2EGuardCheckError = 0x82,
  kE2EAppTagCheckError = 0x83,
  kE2EReferenceTagCheckError = 0x84,
  kCompareFailure = 0x85,
  kAccessDenied = 0x86,
  kDeallocOrUnwrittenLogicalBlck = 0x87,

  // Path Related:
  kInternalPathError = 0x0,
  kAsymmetricAccessPersistentLoss = 0x01,
  kAsymmetricAccessInaccessible = 0x02,
  kAsymmetricAccessTransition = 0x03,
  kControllerPathingError = 0x60,
  kHostPathingError = 0x70,
};

// Used to determine if command uses PRP (physical region page) or SGLs (scatter
// gather lists)
enum class TransferMode : uint8_t {
  // The command uses PRPs (physical region page) for any associated data or
  // metadata transfer. This should be used for all admin commands.
  kPRP = 0x0,
  // Metadata Pointer (MPTR) contains an address of a single contiguous physical
  // buffer that is byte aligned.
  kSGLWithContiguousBuff = 0x1,
  // Metadata Pointer (MPTR) contains an address of an SGL segment containing
  // exactly one SGL Descriptor that is qword aligned.
  kSGLWithSGLDescriptor = 0x2,  // NVMe 1.2
};

// Structure that's used in different commands.
struct [[maybe_unused]] CommonDWord {
  // Opcode for the command to be executed.
  NvmeOpcode opcode : 8;           // OPC
  FusedMode fused_op : 2;          // FUSE
  uint8_t reserved : 4;            // (reserved)
  TransferMode data_transfer : 2;  // PSDT
  uint16_t command_id;             // CID

  bool operator==(const CommonDWord& other) const noexcept = default;
};
static_assert(sizeof(CommonDWord) == sizeof(uint32_t),
              "CommonDWord should be 32 bits.");

// Physical Region Page, PRP, entry definitions.
// PRP are defined by a page base address (PBA) and its offset. The offset is
// defined by the bit index 2 to N where N is defined by the CC.MPS settings
// and the rest of the bits N to 64 is the PBA.
typedef uint64_t PRPEntry;
const uint64_t kPRPReservedMask = ~static_cast<uint64_t>(0x3);

// Alignment requirement for the PRP list in SQE PRP2.
// go/nvme-1.4 section 4.3 Physical Region Page Entry and List
// The first PRP List entry (i.e., the first pointer to a memory page
// containing additional PRP entries) that if present is typically contained in
// the PRP Entry 2 location within the command, shall be qword aligned and may
// also have a non-zero offset within the memory page.
const uint64_t kPrpListReservedMask = ~static_cast<uint64_t>(0x7);

enum class SglDescriptorType : uint8_t {
  kDataBlock = 0,           // NVMe 1.1
  kBitBucket = 1,           // NVMe 1.1
  kSegment = 2,             // NVMe 1.1
  kLastSegment = 3,         // NVMe 1.1
  kKeyedDataBlock = 4,      // NVMe 1.3
  kTransportDataBlock = 5,  // NVMe 1.3
  kVendorSpecific = 15,     // NVMe 1.1
};

enum class SglDescriptorSubtype : uint8_t {
  kAddress = 0,
  kOffset = 1,
};

struct [[maybe_unused]] SglDescriptor {
  // Address field specifies the starting 64bit memory address of the next SGL.
  // Note this is not set for the kBitBucket (that is reserved in the spec).
  uint64_t address;

  // For kDataBlock:
  //   Length field set to 0, means no data to be transferred. This is valid. If
  //   the value address + length wraps around e.g. address + length < address,
  //   this will be deemed as an error.
  // For kBitBucket:
  //   buffer type -
  //     destination buffer: defines the number of bytes of source NOT to be
  //     transferred (to discard). Length 0 denotes nothing to be discarded.
  //     source buffer: length field is ignored.
  // For kSegment OR kLastSegment:
  //   Length in bytes of the next (and last for kLastSegment) segment. The
  //   length must be non-zero and a multiple of 16. If the value address +
  //   length wraps around e.g. address + length < address, this will be deemed
  //   as an error.
  uint32_t length;

  // Next three bytes are reserved
  uint8_t reserved[3];  // (reserved)

  SglDescriptorSubtype descriptor_subtype : 4;  // byte 15, bits [3:0].
  SglDescriptorType descriptor_type : 4;        // byte 15, bits [7:4].

  bool operator==(const SglDescriptor& other) const noexcept = default;
};
static_assert(sizeof(SglDescriptor) == 16, "SglDescriptor should be 16 bytes.");

// Note the specification allows Admin and NVM vendor specific commands.
// Currently, we do not support a particular vendor's specific commands.

//////////////////////////
// Command structure used by both Admin and NVM (I/O) commands.
struct [[maybe_unused]] SubmissionQueueEntry {
  CommonDWord cdw0;

  // Field specifies the namespace ID that this command applies to. If the field
  // is not used, the value must be 0 then. If the command is applied to all
  // namespaces, then the value will be set to 0xffffffff.
  uint32_t namespace_identifier;  // NSID

  uint8_t reserved[8];

  // For Admin commands, this is the address of contiguous physical buffer of
  // metadata. Only used if metadata is not interleaved with logical block data.
  //
  // For NVM (I/O) commands, if dword0.data_transfer is set to 0, then you can
  // treat the ptr the same as the admin command. Otherwise if
  // dword0.data_transfer is set to 1, then this field contains the address of
  // an SGL segment containing exactly one SGL descriptor.
  uint64_t metadata_ptr;  // MPTR

  // Data to transfer.
  // For Admin commands, you must only use the PRP entries.
  // For NVM (I/O) commands, if dword0.data_transfer is set to 0, then use the
  // PRP entries. Otherwise if set to 1, then use the sgl_entry.
  union DataEntry {
    struct PRP {
      PRPEntry one;
      // If spans more than two pages, then this is a list.}
      PRPEntry two;
    } prp_entry;
    SglDescriptor sgl_entry;
  } entry;  // DPTR

  // These fields are command specific.
  uint32_t cdw10;
  uint32_t cdw11;
  uint32_t cdw12;
  uint32_t cdw13;
  uint32_t cdw14;
  uint32_t cdw15;

  bool operator==(const SubmissionQueueEntry& other) const noexcept {
    return nvme_abi_memcmp(this, &other, sizeof(SubmissionQueueEntry)) == 0;
  }
};
static_assert(sizeof(SubmissionQueueEntry) == kSubmissionQueueEntrySizeBytes,
              "SubmissionQueueEntry should be 64 bytes.");

struct [[maybe_unused]] StatusStructure {
  // Identifies whether a completion queue entry is new. At t0, the guest will
  // have all these values set to 0. When entries are complete the device will
  // invert these. These values will flip flop depending on the pass. Read:
  // control really just cares about inverting this bit. The host uses the
  // values to determine phases.
  unsigned int phase_tag : 1;  // P

  // Status or error code associated for the queue entry.
  StatusCode status_code : 8;           // SC
  StatusCodeType status_code_type : 3;  // SCT
  uint8_t command_retry_delay : 2;      // CRD

  // If set to 1, there is more status information for this command as part of
  // the error information log that may be retrieved with the Get Log Page
  // command.
  bool more : 1;  // M

  // If set to 1, if the same command was re-submitted it is expected to fail.
  // If a command was aborted due to timeout, then this field must be set to
  // 0.
  bool do_not_retry : 1;  // DNR

  bool ok() const {
    return status_code == StatusCode::kSuccess &&
           status_code_type == StatusCodeType::kGeneric;
  }
} __attribute__((__packed__));
static_assert(sizeof(StatusStructure) == sizeof(uint16_t),
              "StatusStructure should be 16bits");

// For comparing StatusStructures with EXPECT_EQ() in unit tests. Note: whether
// or not the body of this function is translated into a 16-bit comparison
// depends on the compiler.
static inline bool operator==(const StatusStructure& lhs,
                              const StatusStructure& rhs) noexcept {
  return lhs.phase_tag == rhs.phase_tag && lhs.status_code == rhs.status_code &&
         lhs.status_code_type == rhs.status_code_type &&
         lhs.command_retry_delay == rhs.command_retry_delay &&
         lhs.more == rhs.more && lhs.do_not_retry == rhs.do_not_retry;
}

static inline bool operator!=(const StatusStructure& lhs,
                              const StatusStructure& rhs) noexcept {
  return !(lhs == rhs);
}

static inline bool operator<(const StatusStructure& lhs,
                             const StatusStructure& rhs) noexcept {
  uint16_t lhs_u16, rhs_u16;
  using ::std::memcpy;
  memcpy(&lhs_u16, &lhs, sizeof(uint16_t));
  memcpy(&rhs_u16, &rhs, sizeof(uint16_t));
  return lhs_u16 < rhs_u16;
}

struct [[maybe_unused]] CompletionQueueEntry {
  uint32_t cdw0;
  uint32_t reserved;

  // Defines the current head pointer. This is used to indicate to the guest the
  // submission queue entries that have been consumed and may be reused for new
  // entries.
  uint16_t submission_head_pointer;  // SQHD

  // Indicates which submission this entry was issued to. The guest can use
  // this when more than one submission queue shares a single completion queue.
  uint16_t submission_identifier;  // SQID

  // Identifier of the command that is being completed.
  uint16_t command_identifier;  // CID

  // See struct definition for information on this field.
  StatusStructure status_field;  // SF

  bool operator==(const CompletionQueueEntry& other) const noexcept = default;
};
static_assert(sizeof(CompletionQueueEntry) == kCompletionQueueEntrySizeBytes,
              "CompletionQueueEntry should be 16 bytes");

// Command specific structures.

// DWORD 0 of an Abort completion.
struct [[maybe_unused]] AbortCompletionDword0 {
  bool not_aborted : 1;
  uint32_t reserved : 31;

  bool operator==(const AbortCompletionDword0& other) const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(AbortCompletionDword0) == sizeof(uint32_t));

// Lowest three bits of DWORD 0 of an Asynchronous Event Request completion.
enum class AsyncEventType : uint8_t {
  kErrorStatus = 0,
  kHealthStatus = 1,
  kNotice = 2,
  kIoCommandSetSpecific = 6,
  kVendorSpecific = 7,
};

// DWORD 0 of an Asynchronous Event Request completion.
struct [[maybe_unused]] AsyncEventInfo {
  AsyncEventType type : 3;
  uint8_t reserved_1 : 5;
  uint8_t async_event_info;
  uint8_t log_page_identifier;
  uint8_t reserved_2;

  bool operator==(const AsyncEventInfo& other) const noexcept = default;
};
static_assert(sizeof(AsyncEventInfo) == sizeof(uint32_t));

enum class IdentifyType : uint8_t {
  kNamespace = 0x0,
  kController = 0x1,
  kActiveNsIDList = 0x2,
  kNsIdDescList = 0x3,
  kNvmSetList = 0x4,
  kAllocatedNsIdList = 0x10,
  kNsByAllocatedNsId = 0x11,
  kAttachedCtrlsForNsId = 0x12,
  kExistingCtrlList = 0x13,
  kPrimaryCtrlCapabilities = 0x14,
  kSecondaryCtrlList = 0x15,
  kNsGranularityList = 0x16,
  kUuidList = 0x17,
};

struct [[maybe_unused]] PowerStateDescriptor {
  uint16_t max_power;
  uint8_t reserved_one;
  uint8_t max_power_scale : 1;
  uint8_t non_operational_state : 1;
  uint8_t reserved_two : 6;
  uint32_t entry_latency;
  uint32_t exit_latency;
  uint8_t relative_read_throughput : 5;
  uint8_t reserved_three : 3;
  uint8_t relative_read_latency : 5;
  uint8_t reserved_four : 3;
  uint8_t relative_write_throughput : 5;
  uint8_t reserved_five : 3;
  uint8_t relative_write_latency : 5;
  uint8_t reserved_six : 3;
  uint8_t reserved_seven[16];

  bool operator==(const PowerStateDescriptor& other) const noexcept = default;
};
static_assert(sizeof(PowerStateDescriptor) == 32,
              "PowerStateDescriptor should be 32 bytes");

struct [[maybe_unused]] CtrlAttrs {
  bool ex_host_id : 1;                                    // HIDS
  bool non_op_pwr_perm_mode : 1;                          // NOPSPM
  bool nvm_sets : 1;                                      // NSETS
  bool read_recovery_levels : 1;                          // RRLVLS
  bool endurance_groups : 1;                              // EGS
  bool predictable_latency : 1;                           // PLM
  bool traffic_based_keep_alive : 1;                      // TBKAS
  bool ns_granularity : 1;                                // NG
  bool sq_associations : 1;                               // SQA
  bool uuid_list : 1;                                     // ULIST
  bool multi_domain_subsystem : 1;                        // MDS
  bool fixed_capacity_management : 1;                     // FCM
  bool variable_capacity_management : 1;                  // VCM
  bool delete_endurance_group : 1;                        // DEG
  bool delete_nvm_set : 1;                                // DNVMS
  bool extended_lba_formats_supported : 1;                // ELBAS
  bool mdts_and_size_limits_exclude_metadata : 1;         // MEM
  bool hmb_restrict : 1;                                  // HMBR
  bool reservations_and_host_identifier_interaction : 1;  // RHII
  bool flexible_data_placement : 1;                       // FDPS

  uint16_t reserved : 12;  // (reserved)

  bool operator==(const CtrlAttrs& other) const noexcept = default;
};
static_assert(sizeof(CtrlAttrs) == 4, "CtrlAttrs should be 4 bytes");

// See NVMe spec version 1.4, Identify Controller Data Structure (Figure 251),
// Firmware Updates (FRMW) field (byte 260).
struct [[maybe_unused]] FirmwareUpdates {
  bool first_slot_read_only : 1;
  uint8_t num_slots_supported : 3;
  bool can_activate_without_reset : 1;
  uint8_t reserved : 3;

  bool operator==(const FirmwareUpdates& other) const noexcept = default;
};
static_assert(sizeof(FirmwareUpdates) == sizeof(uint8_t));

// See NVMe spec version 1.4, Figure 112, Log Page Attributes (LPA) field.
struct [[maybe_unused]] LogPageAttributes {
  bool namespace_smart_information : 1;
  bool commands_supported_and_effects : 1;
  bool extended_get_log_page : 1;
  bool telemetry_logs : 1;
  bool persistent_event_log : 1;
  uint8_t reserved : 3;

  bool operator==(const LogPageAttributes& other) const noexcept = default;
};
static_assert(sizeof(LogPageAttributes) == sizeof(uint8_t));

struct [[maybe_unused]] OptNVMCmdSupport {
  bool compare : 1;              // NVMe 1.0
  bool write_uncorrectable : 1;  // NVMe 1.0
  bool dataset_management : 1;   // NVMe 1.0
  bool write_zeroes : 1;         // NVMe 1.1
  bool save_non_zero : 1;        // NVMe 1.1
  bool reservations : 1;         // NVMe 1.1
  bool timestamp : 1;            // NVMe 1.3
  bool verify : 1;               // NVMe 1.4
  uint8_t reserved;

  bool operator==(const OptNVMCmdSupport& other) const noexcept = default;
};
static_assert(sizeof(OptNVMCmdSupport) == sizeof(uint16_t));

// Whether or not the Flush command supports NSID == 0xffffffff (flush all
// namespaces).
enum class FlushAllSupport : uint8_t {
  kNotIndicated = 0,
  kNotSupported = 2,
  kSupported = 3,
};

struct [[maybe_unused]] VolatileWriteCache {
  bool present : 1;
  FlushAllSupport flush_all_support : 2;  // NVMe 1.4
  uint8_t reserved : 5;

  bool operator==(const VolatileWriteCache& other) const noexcept = default;
};
static_assert(sizeof(VolatileWriteCache) == sizeof(uint8_t));

struct [[maybe_unused]] OptAsyncEvtSupport {
  uint8_t reserved;
  bool namespace_attribute_notice : 1;
  bool firmware_activation_notice : 1;
  bool reserved_two : 1;                       // (reserved)
  bool asym_nmsp_access_chg_notice : 1;        // NVMe 1.4+
  bool pred_lat_evt_agg_log_chg_notice : 1;    // NVMe 1.4+
  bool lba_stat_inf_notice : 1;                // NVMe 1.4+
  bool end_grp_evt_agg_log_pg_chg_notice : 1;  // NVMe 1.4+
  bool reserved_three : 1;                     // (reserved)
  uint8_t reserved_four[2];                    // (reserved)

  bool operator==(const OptAsyncEvtSupport& other) const noexcept = default;
};
static_assert(sizeof(OptAsyncEvtSupport) == sizeof(uint32_t));

enum class SglSupport : uint8_t {
  kNotSupported = 0,  // No SGL support.
  kByteAligned = 1,   // No alignment requirement for data blocks.
  kDwordAligned = 2,  // Data blocks must be aligned on a four byte boundary.
};

struct [[maybe_unused]] SglSupportField {
  SglSupport type : 2;                        // bits 1:0
  bool keyed_sgl_data_block_supported : 1;    // bit 2
  uint32_t reserved : 13;                     // bits 15:03
  bool bit_bucket_descriptor_supported : 1;   // bit 16
  bool byte_aligned_metadata_supported : 1;   // bit 17
  bool sgl_length_may_exceed_data_len : 1;    // bit 18
  bool single_segment_in_mptr_supported : 1;  // bit 19
  bool address_field_supported : 1;           // bit 20
  bool transport_sgl_supported : 1;           // bit 21
  uint32_t reserved2 : 10;                    // bits 31:22

  bool operator==(const SglSupportField& other) const noexcept = default;
};
static_assert(sizeof(SglSupportField) == sizeof(uint32_t));

struct [[maybe_unused]] IdentifyController {
  uint16_t vendor_id;                      // VID
  uint16_t subsystem_vendor_id;            // SSVID
  char serial_number[20];                  // SN
  char model_number[40];                   // MN
  char firmware_rev[8];                    // FR
  uint8_t arbitration_burst;               // RAB
  char ieee_ouid[3];                       // IEEE
  uint8_t multi_path;                      // CMIC, optional
  uint8_t max_data_transfer_size;          // MDTS
  uint16_t controller_id;                  // CNTLID
  uint32_t version;                        // VER, NVMe 1.2+
  uint32_t rtd3_resume_latency;            // RTD3R
  uint32_t rtd3_entry_latency;             // RTD3E
  OptAsyncEvtSupport async_event_support;  // OAES
  CtrlAttrs ctrl_attributes;               // CTRATT
  uint16_t read_recovery_lvls;             // RRLS, optional, NVMe 1.4
  char reserved_zero[9];                   // (reserved)
  char ctrl_type;                          // CNTRLTYPE, NVMe 1.4
  uint8_t fru_guid[16];                    // FGUID, optional
  uint16_t cmd_retry_delay_time[3];        // CRDT*, optional, NVMe 1.4
  char reserved_one[122];
  // admin command set attributes
  uint16_t optional_command_support;             // OACS
  uint8_t abort_command_limit;                   // ACL
  uint8_t async_event_request_limit;             // AERL
  FirmwareUpdates firmware_updates;              // FRMW
  LogPageAttributes log_page_attributes;         // LPA
  uint8_t error_log_page_entries;                // ELPE
  uint8_t num_power_states_supported;            // NPSS
  uint8_t admin_vendor_specific_command_config;  // AVSCC
  uint8_t auto_power_transition_attributes;      // APSTA,   optional
  uint16_t warning_temp_threshold;               // WCTEMP, NVMe 1.2
  uint16_t critical_temp_threshold;              // CCTEMP, NVMe 1.2
  uint16_t max_fw_ativation_time;                // MTFA,    optional
  uint32_t host_buff_preferred_size;             // HMPRE,   optional
  uint32_t host_buff_min_size;                   // HMMIN,   optional
  char total_nvm_cap[16];                        // TNVMCAP. optional
  char unalloc_nvm_cap[16];                      // UNVMCAP, optional
  uint32_t protected_replay_mem_blck_support;    // RPMBS,   optional
  uint16_t extended_test_time;                   // EDSTT,   optional
  uint8_t self_test_opts;                        // DSTO,    optional
  uint8_t fw_update_granularity;                 // FWUG
  uint16_t keep_alive_support;                   // KAS
  uint16_t thermal_mgmt_attributes;              // HCTMA,     optional
  uint16_t min_thermal_mgmt_temp;                // MNTMT,     optional
  uint16_t max_thermal_mgmt_temp;                // MXTMT,     optional
  uint32_t sanitize_capabilities;                // SANICAP,   optional
  uint32_t host_buff_min_descr_size;     // HMMINDS,   optional, NVMe 1.4
  uint16_t host_buff_max_descr_entries;  // HMMAXD,    optional, NVMe 1.4
  uint16_t endurance_grp_id_max;         // ENDGIDMAX, optional, NVMe 1.4
  uint8_t ana_translation_time;          // ANATT,     optional, NVMe 1.4
  uint8_t ana_capabilities;              // ANACAP,    optional, NVMe 1.4
  uint32_t ana_group_id_max;             // ANAGRPMAX, optional, NVMe 1.4
  uint32_t ana_group_id_count;           // NANAGRPID, optional, NVMe 1.4
  uint32_t persistent_event_log_size;    // PELS,      optional, NVMe 1.4
  char reserved_two[156];
  // NVMe command set attributes
  uint8_t submission_queue_entry_size;            // SQES
  uint8_t completion_queue_entry_size;            // CQES
  uint16_t max_outstanding_cmds;                  // MAXCMD, optional for PCIe
  uint32_t max_nsid;                              // NN
  OptNVMCmdSupport optional_nvm_command_support;  // ONCS
  uint16_t fused_operations_support;              // FUSES
  uint8_t format_nvme_attributes;                 // FNA
  VolatileWriteCache volatile_write_cache;        // VWC
  uint16_t atomic_write_unit_normal;              // AWUN
  uint16_t atomic_write_unit_power_fail;          // AWUPF
  uint8_t nvm_vendor_specific_command_config;     // NVSCC
  uint8_t ns_write_protection_capabilities;       // NWPC, NVMe 1.4
  uint16_t atomic_compare_write_unit;             // ACWU
  uint16_t reserved_five;                         // (reserved)
  SglSupportField sgl_support;                    // SGLS
  uint32_t max_allowed_ns_number;                 // MNAN, optional, NVMe 1.4
  char reserved_six[224];                         // (reserved)
  char nvme_qualified_name[256];                  // SUBNQN, NVMe 1.2.1
  char reserved_seven[768];                       // (reserved)
  char reserved_eight[256];                       // (reserved for NVMeoF)
  // Power State Descriptors
  PowerStateDescriptor power_states[32];  // LBAF*, First one is mandatory.
  // Vendor Specific
  char reserved_nine[1024];

  bool operator==(const IdentifyController& other) const noexcept = default;
};
static_assert(sizeof(IdentifyController) == kIdentifySize,
              "IdentifyController should be 4096 bytes");
static_assert(kMaxSubnqnSize < sizeof(IdentifyController::nvme_qualified_name),
              "nvme_qualified_name must fit up to 223 bytes");

const uint16_t kSupportsDoorbellBuffer = 1 << 8;
// We still have to support this one - see b/66681426
const uint16_t kSupportsDoorbellBufferDeprecated = 1 << 7;

struct [[maybe_unused]] LBAFormat {
  uint16_t metadata_size;            // MS
  uint8_t data_size;                 // LBADS
  uint8_t relative_performance : 2;  // RP
  uint8_t reserved : 6;              // (reserved)

  bool operator==(const LBAFormat& other) const noexcept = default;
};
static_assert(sizeof(LBAFormat) == sizeof(uint32_t),
              "LBAFormat should be 4 bytes");

struct [[maybe_unused]] ResCapBits {
  bool persist_power_loss : 1;
  bool write_exclusive : 1;
  bool exclusive_access : 1;
  bool write_exclusive_regs_only : 1;
  bool exclusive_access_regs_only : 1;
  bool write_exclusive_all_regs : 1;
  bool exclusive_access_all_regs : 1;
  bool ignore_existing_key : 1;  // NVMe 1.3

  bool operator==(const ResCapBits& other) const noexcept = default;
};
static_assert(sizeof(ResCapBits) == sizeof(uint8_t), "");

// Defines which data protection features are supported by a namespace.
struct [[maybe_unused]] DataProtectionCapabilities {
  bool protection_type_1 : 1;
  bool protection_type_2 : 1;
  bool protection_type_3 : 1;
  bool pi_at_start_of_md : 1;
  bool pi_at_end_of_md : 1;
  uint8_t reserved : 3;

  bool operator==(const DataProtectionCapabilities& other) const noexcept =
      default;
};
static_assert(sizeof(DataProtectionCapabilities) == sizeof(uint8_t));

enum class ProtectionType : uint8_t {
  kNoProtectionInformation = 0,
  // Type 1: controller checks guard and ref tag.
  kType1 = 1,
  // Type 2: controller checks guard and ref tag. The ref tag starts at ILBRT /
  // EILBRT and is increased by one for each logical block.
  kType2 = 2,
  // Type 3: controller checks guard only. ref tag and app tag are controlled by
  // the initiator.
  kType3 = 3,
};

struct [[maybe_unused]] DataProtectionTypeSettings {
  ProtectionType protection_type : 3;
  bool pi_at_start_of_md : 1;
  uint8_t reserved : 4;

  bool operator==(const DataProtectionTypeSettings& other) const noexcept =
      default;
};
static_assert(sizeof(DataProtectionTypeSettings) == sizeof(uint8_t));

// Value read back from deallocated logical blocks: not reported, 0x00 or 0xff.
enum class DeallocatedReadBehavior : uint8_t {
  kNotReported = 0,
  kAllBytesZero = 1,
  kAllBytesFf = 2,
};

struct [[maybe_unused]] DeallocateBlockFeatures {
  DeallocatedReadBehavior deallocated_read_behavior : 3;  // NVMe 1.3
  bool write_zeroes_supports_deallocate : 1;              // NVMe 1.3
  bool guard_valid_for_deallocated_blocks : 1;            // NVMe 1.3
  uint8_t reserved : 3;

  bool operator==(const DeallocateBlockFeatures& other) const noexcept =
      default;
};
static_assert(sizeof(DeallocateBlockFeatures) == sizeof(uint8_t));

struct [[maybe_unused]] NamespaceGloballyUniqueId {
  uint64_t vendor_extension_id;  // Vendor specific extension
  uint8_t oui[3];                // IEEE designated Organizationally Unique ID
  uint8_t org_extension_id[5];   // Organization extension identifier

  bool operator==(const NamespaceGloballyUniqueId& other) const noexcept =
      default;
} __attribute__((__packed__));
static_assert(sizeof(NamespaceGloballyUniqueId) == 16);

// Namespace identifier types used to indicate the ID type for a namespace ID
// descriptor.
enum class NamespaceIdType : uint8_t {
  kEuid = 0x1,   // IEEE extended unique identifier (EUI64).
  kNguid = 0x2,  // Namespace globally unique identifier (NGUID).
  kUuid = 0x3    // Namespace universally unique identifier (UUID).
};

// Common fields across the three Namespace ID descriptor structures below:
// NamespaceIdDescEuid, NamespaceIdDescNguid, NamespaceIdDescUuid.
struct [[maybe_unused]] NamespaceIdDescHeader {
  NamespaceIdType id_type;  // NIDT
  uint8_t length;           // NIDL
  uint16_t reserved_bytes;  // (reserved)

  bool operator==(const NamespaceIdDescHeader& other) const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(NamespaceIdDescHeader) == 4);

// Namespace ID descriptor containing an IEEE EUID.
struct [[maybe_unused]] NamespaceIdDescEuid {
  NamespaceIdDescHeader header;
  uint64_t euid;

  // Returns a formatted NamespaceIdDescEuid.
  static NamespaceIdDescEuid Create(uint64_t big_endian_euid) {
    return {.header = {.id_type = NamespaceIdType::kEuid,
                       .length = sizeof(uint64_t)},
            .euid = big_endian_euid};
  }

  bool operator==(const NamespaceIdDescEuid& other) const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(NamespaceIdDescEuid) == 12);

// Namespace ID descriptor containing an NGUID.
struct [[maybe_unused]] NamespaceIdDescNguid {
  NamespaceIdDescHeader header;
  NamespaceGloballyUniqueId nguid;

  // Returns a formatted NamespaceIdDescNguid.
  static NamespaceIdDescNguid Create(
      NamespaceGloballyUniqueId big_endian_nguid) {
    return {.header = {.id_type = NamespaceIdType::kNguid,
                       .length = sizeof(NamespaceGloballyUniqueId)},
            .nguid = big_endian_nguid};
  }

  bool operator==(const NamespaceIdDescNguid& other) const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(NamespaceIdDescNguid) == 20);

// Namespace ID descriptor containing a UUID.
struct [[maybe_unused]] NamespaceIdDescUuid {
  NamespaceIdDescHeader header;
  uint64_t uuid[2];

  // Returns a formatted NamespaceIdDescUuid. `big_endian_uuid` must have 2
  // elements to form a 128-bit UUID.
  static NamespaceIdDescUuid Create(uint64_t big_endian_uuid[]) {
    return {
        .header = {.id_type = NamespaceIdType::kUuid, .length = sizeof(uuid)},
        .uuid = {big_endian_uuid[0], big_endian_uuid[1]}};
  }

  bool operator==(const NamespaceIdDescUuid& other) const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(NamespaceIdDescUuid) == 20);

struct [[maybe_unused]] NamespaceFeatures {
  bool thin_provisioning_support : 1;
  bool atomic_write_support : 1;  // Supports NAWUN, NAWUPF, and NACWU
  bool deallocated_logical_block_error_support : 1;
  bool nguid_euid_not_reused : 1;
  // Supports NPWG, NPWA, NPDG, and NPDA
  bool preferred_alignment_granularity_support : 1;
  uint8_t reserved : 3;

  bool operator==(const NamespaceFeatures& other) const noexcept = default;
};
static_assert(sizeof(NamespaceFeatures) == sizeof(uint8_t));

struct [[maybe_unused]] NamespaceAttributes {
  bool write_protected : 1;
  uint8_t reserved : 7;

  bool operator==(const NamespaceAttributes& other) const noexcept = default;
};
static_assert(sizeof(NamespaceAttributes) == sizeof(uint8_t));

struct [[maybe_unused]] FormattedLbaSize {
  uint8_t lba_format_index : 4;
  uint8_t metadata_inline : 1;
  uint8_t reserved : 3;

  bool operator==(const FormattedLbaSize& other) const noexcept = default;
};
static_assert(sizeof(FormattedLbaSize) == sizeof(uint8_t));

struct [[maybe_unused]] IdentifyNamespace {
  uint64_t size;                                            // NSZE
  uint64_t capacity;                                        // NCAP
  uint64_t utilization;                                     // NUSE
  NamespaceFeatures features;                               // NSFEAT
  uint8_t num_lba_formats;                                  // NLBAF
  uint8_t formatted_lba_size;                               // FLBAS
  uint8_t metadata_capabilities;                            // MC
  DataProtectionCapabilities data_protection_capabilities;  // DPC
  DataProtectionTypeSettings data_protection_type;          // DPS
  uint8_t multi_path;                   // NMIC,     optional, MVMe 1.1
  ResCapBits reservation_capabilities;  // RESCAP,   optional, MVMe 1.1
  uint8_t format_progress_indicator;    // FPI,      optional, NVMe 1.2
  DeallocateBlockFeatures
      dealloc_blck_features;               // DLFEAT,   optional, NVMe 1.3
  uint16_t atomic_write;                   // NAWUN.    optional, NVMe 1.2
  uint16_t atomic_write_pwr_fail;          // NAWUPF,   optional, NVMe 1.2
  uint16_t atomic_cmp_write;               // NACWU,    optional, NVMe 1.2
  uint16_t atomic_boundary_size;           // NABSN,    optional, NVMe 1.2
  uint16_t atomic_boundary_offset;         // NABO,     optional, NVMe 1.2
  uint16_t atomic_boundary_size_pwr_fail;  // NABSPF,   optional, NVMe 1.2
  uint16_t optimal_io_boundary;            // NOIOB,    optional, NVMe 1.3
  char nvm_capacity[16];                   // NVMCAP,   optional, NVMe 1.2
  uint16_t preferred_write_granularity;    // NPWG,     optional, NVMe 1.4
  uint16_t preferred_write_alignment;      // NPWA,     optional, NVMe 1.4
  uint16_t preferred_dealloc_granularity;  // NPDG,     optional, NVMe 1.4
  uint16_t preferred_dealloc_alignment;    // NPDA,     optional, NVMe 1.4
  uint16_t optimal_write_size;             // NOWS,     optional, NVMe 1.4
  char reserved_one[18];                   // (reserved)
  uint32_t ana_group_id;                   // ANAGRPID, optional, NVMe 1.4
  char reserved_two[3];                    // (reserved)
  NamespaceAttributes ns_attributes;       // NSATTR,   optional, NVMe 1.4
  uint16_t nvm_set_id;                     // NVMSETID, optional, NVMe 1.4
  uint16_t endurance_grp_id;               // ENDGID,   optional, NVMe 1.4
  NamespaceGloballyUniqueId nguid;         // NGUID
  uint64_t ieee_euid;                      // EUI64, NVMe 1.1
  LBAFormat lba_format[16];                // LBAF*, First one is mandatory.
  char reserved_three[192];
  char vendor_specific[3712];

  bool operator==(const IdentifyNamespace& other) const noexcept = default;
};
static_assert(sizeof(IdentifyNamespace) == kIdentifySize,
              "IdentifyNamespace should be 4096 bytes");

// Use by GetFeatures
struct [[maybe_unused]] LBARangeType {
  uint8_t type;
  uint8_t attributes;
  uint8_t reserved_one[14];
  uint64_t starting_lba;
  uint64_t num_blocks;
  uint8_t uniq_id[16];
  uint8_t reserved_two[16];

  bool operator==(const LBARangeType& other) const noexcept = default;
};
static_assert(sizeof(LBARangeType) == 64, "LBARangeType should be 64 bytes");

// Used by GetFeatures / SetFeatures.
struct HostIdentifier {
  uint64_t hostid[2];  // HOSTID

  bool operator==(const HostIdentifier& other) const noexcept = default;
};
static_assert(sizeof(HostIdentifier) == 16,
              "HostIdentifier should be 16 bytes");

// Used by GetFeature and SetFeature commands.
enum class FeatureType : uint8_t {
  kReserved = 0x0,
  kArbitration = 0x1,                // mandatory
  kPowerMgmt = 0x2,                  // mandatory
  kLbaRangeType = 0x3,               // optional
  kTempThreshold = 0x4,              // mandatory
  kErrorRecovery = 0x5,              // mandatory
  kVolatileWriteCache = 0x6,         // optional
  kNumQueues = 0x7,                  // mandatory
  kInterruptCoalescing = 0x8,        // mandatory on PCIe
  kInterruptVectorConfig = 0x9,      // mandatory on PCIe
  kWriteAtomicity = 0xA,             // mandatory
  kAsyncEventConfig = 0xB,           // mandatory
  kAutoPowerStateTrans = 0xC,        // NVMe 1.1, optional
  kHostMemoryBuffer = 0xD,           // NVMe 1.2, optional
  kTimestamp = 0xE,                  // NVMe 1.3, optional
  kKeepAliveTimer = 0xF,             // NVMe 1.2.1, optional
  kHostControlledThermal = 0x10,     // NVMe 1.3, optional
  kNonOpPowerStateCfg = 0x11,        // NVMe 1.3, optional
  kReadRecoveryLevelCfg = 0x12,      // NVMe 1.4, optional
  kPredictableLatencyCfg = 0x13,     // NVMe 1.4, optional
  kPredictableLatencyWindow = 0x14,  // NVMe 1.4, optional
  kLbaStatusInfoInterval = 0x15,     // NVMe 1.4, optional
  kHostBehaviorSupport = 0x16,       // NVMe 1.4, optional
  kSanitizeConfig = 0x17,            // NVMe 1.4, optional
  kEnduranceGrpEventCfg = 0x18,      // NVMe 1.4, optional
  // 0x19 - 0x77 Reserved
  // 0x78 - 0x7F NVMe Management Interface Specification
  kSoftwareProgressMarker = 0x80,       // optional
  kHostIdentifier = 0x81,               // NVMe 1.1, mandatory if reservations
  kReservationNotificationMask = 0x82,  // NVMe 1.1, mandatory if reservations
  kReservationPersistence = 0x83,       // NVMe 1.1, mandatory if reservations
  kNsWriteProtectionConfig = 0x84,      // NVMe 1.4, optional
  // 0x85 - 0xBF Reserved
  // 0xC0 - 0xFF Vendor specific
};

// Used by GetFeatures
enum class GetFeaturesSelect : uint8_t {
  kCurrent = 0x0,
  kDefault = 0x1,
  kSaved = 0x2,
  kSupportedCapabilities = 0x3,
};

struct [[maybe_unused]] GetFeaturesCdw10 {
  FeatureType feature;
  GetFeaturesSelect select : 3;
  uint32_t reserved : 21;

  bool operator==(const GetFeaturesCdw10& other) const noexcept = default;
};
static_assert(sizeof(GetFeaturesCdw10) == sizeof(uint32_t));

struct [[maybe_unused]] SetFeaturesCdw10 {
  FeatureType feature_identifier;
  uint32_t reserved : 23;
  bool save : 1;

  bool operator==(const SetFeaturesCdw10& other) const noexcept = default;
};
static_assert(sizeof(SetFeaturesCdw10) == sizeof(uint32_t));

// Used by SetFeatures for reservation persistence (go/nvme-1.4, Figure 320)
struct [[maybe_unused]] ReservationPersistenceCdw11 {
  uint32_t reserved : 31;
  bool ptpl : 1;

  bool operator==(const ReservationPersistenceCdw11& other) const noexcept =
      default;
};
static_assert(sizeof(ReservationPersistenceCdw11) == sizeof(uint32_t));

// Response to GetFeatures with select == SupportedCapabilities
struct [[maybe_unused]] SupportedCapabilitiesDw0 {
  bool saveable : 1;
  bool namespace_specific : 1;
  bool changeable : 1;
  uint32_t reserved : 29;

  bool operator==(const SupportedCapabilitiesDw0& other) const noexcept =
      default;
};

// Used by DATASET_MGMT command
struct [[maybe_unused]] DatasetMgmtRange {
  uint32_t context_attributes;
  uint32_t length;  // Number of logical blocks. One based.
  uint64_t starting_lba;

  bool operator==(const DatasetMgmtRange& other) const noexcept = default;
};
static_assert(sizeof(DatasetMgmtRange) == 16,
              "DatasetMgmtRange should be 16 bytes");

struct [[maybe_unused]] DatasetMgmtDw10 {
  uint8_t zb_number_of_ranges;  // NR, 0 based value
  uint32_t reserved : 24;       // (reserved)

  bool operator==(const DatasetMgmtDw10& other) const noexcept = default;
};
static_assert(sizeof(DatasetMgmtDw10) == 4, "");

struct [[maybe_unused]] DatasetMgmtDw11 {
  bool opt_read : 1;           // IDR
  bool opt_write : 1;          // IDW
  bool deallocate : 1;         // AD
  uint32_t reserved_one : 29;  // (reserved)

  bool operator==(const DatasetMgmtDw11& other) const noexcept = default;
};
static_assert(sizeof(DatasetMgmtDw11) == 4, "");

// Used by reservation commands.

enum class ReservationType : uint8_t {
  kReserved = 0x0,
  kWriteExclusive = 0x1,
  kExclusiveAccess = 0x2,
  kWriteExclusiveRegsOnly = 0x3,
  kExclusiveAccessRegsOnly = 0x4,
  kWriteExclusiveAllRegs = 0x5,
  kExclusiveAccessAllRegs = 0x6,
};

struct [[maybe_unused]] ReservationReportDw10 {
  uint32_t num_dwords;  // NUMD

  bool operator==(const ReservationReportDw10& other) const noexcept = default;
};

// Corresponds to Figure 389 in go/nvme-1.4. Determines which data structure to
// return when executing Reservation Reports (RegisteredCtrlData vs.
// RegisteredCtrlExData).
struct [[maybe_unused]] ReservationReportDw11 {
  bool extended_data_structure : 1;  // EDS
  uint32_t reserved : 31;

  bool operator==(const ReservationReportDw11& other) const noexcept = default;
};

// Corresponds to Figure 317 in go/nvme-1.4 and is set by the host
// when requesting the use of the extended 128-bit host ID. Used by admin
// commands to verify whether this feature has been enabled.
struct [[maybe_unused]] ExtendedHostIdentifierDw11 {
  bool enable_extended_host_id : 1;  // EXHID
  uint32_t reserved : 31;

  bool operator==(const ExtendedHostIdentifierDw11& other) const noexcept =
      default;
};

struct [[maybe_unused]] ReservationStatusData {
  uint32_t generation;  // GEN
  // Note that the RTYPE value `kReserved` means no reservation is held. See:
  // NVMe spec 1.3d, Figure 229; NVMe spec 1.4c, Figure 384
  ReservationType type;                                        // RTYPE.
  uint16_t registered_ctrl_count __attribute__((__packed__));  // REGCTL
  uint16_t reserved_zero __attribute__((__packed__));          // (reserved)
  uint8_t persist_power_loss;                                  // PTPLS
  char reserved_one[14];                                       // (reserved)

  bool operator==(const ReservationStatusData& other) const noexcept = default;
};
static_assert(sizeof(ReservationStatusData) == 24, "");

struct [[maybe_unused]] ReservationStatusExtData {
  ReservationStatusData reservation_status_data;
  char reserved_two[40];

  bool operator==(const ReservationStatusExtData& other) const noexcept =
      default;
};

struct CtrlRegStatus {
  bool current_holder : 1;
  uint8_t reserved_one : 7;

  bool operator==(const CtrlRegStatus& other) const noexcept = default;
};
static_assert(sizeof(CtrlRegStatus) == 1, "");

struct [[maybe_unused]] RegisteredCtrlData {
  uint16_t ctrl_id;      // CNTLID
  CtrlRegStatus status;  // RCSTS
  uint8_t reserved[5];   // (reserved)
  uint64_t host_id;      // HOSTID
  uint64_t res_key;      // RKEY

  bool operator==(const RegisteredCtrlData& other) const noexcept = default;
};
static_assert(sizeof(RegisteredCtrlData) == 24, "");

struct [[maybe_unused]] RegisteredCtrlExData {
  uint16_t ctrl_id;          // CNTLID
  CtrlRegStatus status;      // RCSTS
  uint8_t reserved_one[5];   // (reserved)
  uint64_t res_key;          // RKEY
  uint8_t host_id[16];       // EXHID
  uint8_t reserved_two[32];  // (reserved)

  bool operator==(const RegisteredCtrlExData& other) const noexcept = default;
};
static_assert(sizeof(RegisteredCtrlExData) == 64, "");

struct [[maybe_unused]] ReservationAcquireData {
  uint64_t current_key;  // CRKEY
  uint64_t preempt_key;  // PRKEY

  bool operator==(const ReservationAcquireData& other) const noexcept = default;
};
static_assert(sizeof(ReservationAcquireData) == 16, "");

enum class RegisterAction : uint8_t {
  kRegisterKey = 0,
  kUnregisterKey = 1,
  kReplaceKey = 2,
};

enum class PwrLossResChange : uint8_t {
  kNoChange = 0,
  kReserved = 1,
  // Reservations are released and registrants are cleared on a power on.
  kReleased = 2,
  // Reservations and registrants persist across a power loss.
  kPersist = 3,
};

enum class AcqAction : uint8_t {
  kAcquire = 0,
  kPreempt = 1,
  kPreemptAndAbort = 2,
};

struct [[maybe_unused]] AcqReservationDw10 {
  AcqAction action : 3;          // RACQA
  bool ignore_existing_key : 1;  // IEKEY
  uint8_t reserved_one : 4;      // (reserved)
  ReservationType type;          // RTYPE
  uint16_t reserved_two;         // (reserved)

  bool operator==(const AcqReservationDw10& other) const noexcept = default;
};
static_assert(sizeof(AcqReservationDw10) == 4, "");

struct [[maybe_unused]] RegisterReservationDw10 {
  RegisterAction action : 3;         // RREGA
  bool ignore_existing_key : 1;      // IEKEY
  uint32_t reserved : 26;            // (reserved)
  PwrLossResChange change_ptpl : 2;  // CPTPL

  bool operator==(const RegisterReservationDw10& other) const noexcept =
      default;
};
static_assert(sizeof(RegisterReservationDw10) == 4, "");

struct [[maybe_unused]] RegisterReservationData {
  uint64_t current_key;  // CRKEY
  uint64_t new_key;      // NRKEY

  bool operator==(const RegisterReservationData& other) const noexcept =
      default;
};
static_assert(sizeof(RegisterReservationData) == 16, "");

enum class ReleaseAction : uint8_t {
  kRelease = 0,
  kClear = 1,
};

struct [[maybe_unused]] ReleaseReservationDw10 {
  ReleaseAction action : 3;      // RRELA
  bool ignore_existing_key : 1;  // IEKEY
  uint8_t reserved_one : 4;      // (reserved)
  ReservationType type;          // RTYPE
  uint16_t reserved_two;         // (reserved)

  bool operator==(const ReleaseReservationDw10& other) const noexcept = default;
};
static_assert(sizeof(ReleaseReservationDw10) == 4, "");

// This struct is the same for deleting completion and submission queues.
struct [[maybe_unused]] DeleteQueueDw10 {
  uint16_t queue_id;  // QID
  uint16_t reserved;  // (reserved)

  bool operator==(const DeleteQueueDw10& other) const noexcept = default;
};
static_assert(sizeof(DeleteQueueDw10) == 4);

// This struct is the same for create completion queue and create submission
// queue commands.
struct [[maybe_unused]] CreateIoQueueDw10 {
  uint16_t queue_id;    // QID
  uint16_t queue_size;  // QSIZE, 0 based value

  bool operator==(const CreateIoQueueDw10& other) const noexcept = default;
};
static_assert(sizeof(CreateIoQueueDw10) == 4);

struct [[maybe_unused]] CreateIoCompQueueDw11 {
  bool physically_contiguous : 1;  // PC
  bool interrupts_enabled : 1;     // IEN
  uint16_t reserved_one : 14;      // (reserved)
  uint16_t msix_vector;            // IV

  bool operator==(const CreateIoCompQueueDw11& other) const noexcept = default;
};

static_assert(sizeof(CreateIoCompQueueDw11) == 4);

enum class QueuePriority : uint8_t {
  kUrgent = 0,
  kHigh = 1,
  kMedium = 2,
  kLow = 3
};

struct [[maybe_unused]] CreateIoSubQueueDw11 {
  bool physically_contiguous : 1;    // PC
  QueuePriority queue_priority : 2;  // QPRIO
  uint16_t reserved_one : 13;        // (reserved)
  uint16_t comp_queue_id;            // CQID

  bool operator==(const CreateIoSubQueueDw11& other) const noexcept = default;
};

static_assert(sizeof(CreateIoSubQueueDw11) == 4);

struct [[maybe_unused]] IdentifyDw10 {
  IdentifyType c_or_n_structure;  // CNS
  uint8_t reserved;               // (reserved)
  uint16_t controller_id;         // CNTID

  bool operator==(const IdentifyDw10& other) const noexcept = default;
};
static_assert(sizeof(IdentifyDw10) == 4);

struct [[maybe_unused]] AbortDw10 {
  uint16_t submission_queue_id;  // SQID
  uint16_t command_id;           // CID

  bool operator==(const AbortDw10& other) const noexcept = default;
};
static_assert(sizeof(AbortDw10) == 4);

enum class AsyncEvtType : uint8_t {
  kErrorStatus = 0x0,
  kSmartHealthStatus = 0x1,
  kNotice = 0x2,
  kIoCommandSetSpecificStatus = 0x6,
  kVendorSpecific = 0x7,
};

enum class LogPageId : uint8_t {
  kErrorInfo = 0x01,                // Ctrl scope
  kSmartHealthInfo = 0x02,          // Namespace or NVM scope
  kFirmwareSlotInfo = 0x03,         // NVM scope
  kChangedNamespaceList = 0x04,     // Ctrl scope
  kCmdsSupportedAndEffects = 0x05,  // Ctrl scope
  kDeviceSelfTest = 0x06,           // Ctrl scope
  kTelemetryHostInitiated = 0x07,   // Ctrl scope
  kTelemetryCtrlInitiated = 0x08,   // Ctrl scope
  kEnduranceGrpInfo = 0x09,         // NVM scope, NVMe 1.4+
  kPredictableLatPerNvmSet = 0x0A,  // NVM scope, NVMe 1.4+
  kPredictableLatEvtAggr = 0x0B,    // NVM scope, NVMe 1.4+
  kAsymmNmspAccess = 0x0C,          // Ctrl scope, NVMe 1.4+
  kPersistentEvtLog = 0x0D,         // NVM scope, NVMe 1.4+
  kLbaStatusInfo = 0x0E,            // Ctrl scope, NVMe 1.4+
  kEnduranceGrpEvtAggr = 0x0F,      // NVM scope, NVMe 1.4+
  kDiscovery = 0x70,
  kReservationNotification = 0x80,  // NVM specific, Ctrl scope
  kSanitizeStatus = 0x81,           // NVM specific, NVM scope
};

enum class AsyncEvtInfoNotice : uint8_t {
  kNamespaceAttributeChanged = 0x00,
  kFirmwareActivationStarting = 0x01,
  kTelemetryLogChanged = 0x02,
  kAsymmetricNamespaceAccessChange = 0x03,  // NVMe 1.4+
  kPredictableLatEvtAggrLogChange = 0x04,   // NVMe 1.4+
  kLbaStatusInfoAlert = 0x05,               // NVMe 1.4+
  kEnduranceGrpEvtAggrLogPgChange = 0x06    // NVMe 1.4+
};

enum class AsyncInfoEvtErrorStatus : uint8_t {
  kWriteToInvalidDoorbellRegister = 0x00,
  kInvalidDoorbellWriteValue = 0x01,
  kDiagnosticFailure = 0x02,
  kPersistentInternalError = 0x03,
  kTransientInteranlError = 0x04,
  kFirmwareImageLoadError = 0x05,
};

union [[maybe_unused]] AsyncEvtInfo {
  AsyncInfoEvtErrorStatus error_status;
  uint8_t smart_health_status;
  AsyncEvtInfoNotice notice;
  uint8_t cmd_set_specific;

  bool operator==(const AsyncEvtInfo& other) const noexcept {
    return nvme_abi_memcmp(this, &other, sizeof(*this)) == 0;
  };
};
static_assert(sizeof(AsyncEvtInfo) == sizeof(uint8_t));

// Used by Asynchronous Event Request command completion queue entry
struct [[maybe_unused]] AsyncEvtReqCqeDw0 {
  AsyncEvtType evt_type : 3;
  uint8_t reserved1 : 5;
  AsyncEvtInfo evt_info;
  LogPageId log_page_id;
  uint8_t reserved2;

  bool operator==(const AsyncEvtReqCqeDw0& other) const noexcept = default;
};
static_assert(sizeof(AsyncEvtReqCqeDw0) == sizeof(uint32_t));

// Used by Get Log Page command submission queue entry
struct [[maybe_unused]] GetLogPageSqeCdw10 {
  LogPageId log_page_id;
  uint8_t log_specific_field : 4;
  uint8_t reserved : 3;
  bool retain_async_evt : 1;
  uint16_t num_dwords_lower;

  bool operator==(const GetLogPageSqeCdw10& other) const noexcept = default;
};
static_assert(sizeof(GetLogPageSqeCdw10) == sizeof(uint32_t));

// Used by Get Log Page command submission queue entry
struct [[maybe_unused]] GetLogPageSqeCdw11 {
  uint16_t num_dwords_upper;
  uint16_t endurance_group_or_set_id;

  bool operator==(const GetLogPageSqeCdw11& other) const noexcept = default;
};
static_assert(sizeof(GetLogPageSqeCdw11) == sizeof(uint32_t));

// Used by Get Log Page command submission queue entry
struct [[maybe_unused]] GetLogPageSqeCdw14 {
  uint8_t uuid_index : 6;
  uint32_t reserved : 26;

  bool operator==(const GetLogPageSqeCdw14& other) const noexcept = default;
};
static_assert(sizeof(GetLogPageSqeCdw14) == sizeof(uint32_t));

// Used by Get Log Page Host initiated Telemety submission queue entry
struct [[maybe_unused]] GetLogPageTelemetryHeader {
  LogPageId log_page_id;
  uint8_t reserved_one[4];
  char ieee_oui[3];
  uint16_t area1_last_block;
  uint16_t area2_last_block;
  uint16_t area3_last_block;
  uint8_t reserved_two[368];
  uint8_t ctrl_init_data_avail;
  uint8_t ctrl_init_data_gen_num;
  uint8_t reason[128];

  bool operator==(const GetLogPageTelemetryHeader& other) const noexcept =
      default;
};
static_assert(sizeof(GetLogPageTelemetryHeader) == 512);

struct GetLogPageSmartHealthCriticalWarning {
  bool space : 1;
  bool temp : 1;
  bool reliability_degradation : 1;
  bool read_only : 1;
  bool volatile_memory_backup_failed : 1;
  uint8_t reserved : 3;  // (reserved)

  bool operator==(const GetLogPageSmartHealthCriticalWarning& other)
      const noexcept = default;
};
static_assert(sizeof(GetLogPageSmartHealthCriticalWarning) == 1);

struct [[maybe_unused]] GetLogPageSmartHealthInformationLog {
  GetLogPageSmartHealthCriticalWarning critical_warning;
  uint16_t composite_temperature;
  uint8_t available_spare;
  uint8_t available_spare_threshold;
  uint8_t percentage_used;
  uint8_t reserved_one[26];
  uint64_t data_units_read_lsb;
  uint64_t data_units_read_msb;
  uint64_t data_units_written_lsb;
  uint64_t data_units_written_msb;
  uint64_t host_read_commands_lsb;
  uint64_t host_read_commands_msb;
  uint64_t host_write_commands_lsb;
  uint64_t host_write_commands_msb;
  uint64_t controller_busy_time_lsb;
  uint64_t controller_busy_time_msb;
  uint64_t power_cycles_lsb;
  uint64_t power_cycles_msb;
  uint64_t power_on_hours_lsb;
  uint64_t power_on_hours_msb;
  uint64_t unsafe_shutdowns_lsb;
  uint64_t unsafe_shutdowns_msb;
  uint64_t media_and_data_integrity_errors_lsb;
  uint64_t media_and_data_integrity_errors_msb;
  uint64_t num_error_information_log_entries_lsb;
  uint64_t num_error_information_log_entries_msb;
  uint32_t warning_composite_temperature_time;
  uint32_t critical_composite_temperature_time;
  uint16_t temperature_sensor_1;
  uint16_t temperature_sensor_2;
  uint16_t temperature_sensor_3;
  uint16_t temperature_sensor_4;
  uint16_t temperature_sensor_5;
  uint16_t temperature_sensor_6;
  uint16_t temperature_sensor_7;
  uint16_t temperature_sensor_8;
  uint32_t thermal_management_temperature_1_transition_count;
  uint32_t thermal_management_temperature_2_transition_count;
  uint32_t total_time_thermal_management_temperature_1;
  uint32_t total_time_thermal_management_temperature_2;
  uint8_t reserved_two[280];

  bool operator==(const GetLogPageSmartHealthInformationLog& other)
      const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(GetLogPageSmartHealthInformationLog) ==
              kSmartHealthLogPageSize);

struct GetLogPageActiveFirmwareInfo {
  uint8_t active_slot : 3;
  uint8_t reserved_one : 1;
  uint8_t next_slot : 3;
  uint8_t reserved_two : 1;

  bool operator==(const GetLogPageActiveFirmwareInfo& other) const noexcept =
      default;
};
static_assert(sizeof(GetLogPageActiveFirmwareInfo) == 1);

struct [[maybe_unused]] GetLogPageFirmwareSlotInformationLog {
  GetLogPageActiveFirmwareInfo info;  // AFI
  uint8_t reserved_one[7];
  char slot_1_version[8];  // FSR1
  char slot_2_version[8];  // FSR2
  char slot_3_version[8];  // FSR3
  char slot_4_version[8];  // FSR4
  char slot_5_version[8];  // FSR5
  char slot_6_version[8];  // FSR6
  char slot_7_version[8];  // FSR7
  uint8_t reserved_two[448];

  bool operator==(const GetLogPageFirmwareSlotInformationLog& other)
      const noexcept = default;
} __attribute__((__packed__));
static_assert(sizeof(GetLogPageFirmwareSlotInformationLog) ==
              kFirmwareSlotLogPageSize);

// Used by Get Features command completion queue entry for async event config in
// CDW0, and Set Features in CDW11.
struct [[maybe_unused]] AsyncEvtConfig {
  GetLogPageSmartHealthCriticalWarning smart_warnings;
  bool namespace_attr_notices : 1;
  bool firmware_act_notices : 1;
  bool telemetry_log_notices : 1;
  uint32_t reserved : 21;  // (reserved)

  bool operator==(const AsyncEvtConfig& other) const noexcept = default;
};
static_assert(sizeof(AsyncEvtConfig) == sizeof(uint32_t));

// NumQueues is used for the number of queues feature identifier of the Get/Set
// Feature admin command. The number of queues do not include admin queues, and
// is 0 based. So, 1 queue is represented by a 0. Using the constructor below
// will take the actual queue count, and subtract 1 to make the count
// zero based.
struct [[maybe_unused]] NumQueues {
  uint16_t num_sub_queues;   // 0 based
  uint16_t num_comp_queues;  // 0 based
  NumQueues(uint16_t sub_queues, uint16_t comp_queues)
      : num_sub_queues(sub_queues - 1), num_comp_queues(comp_queues - 1) {}

  bool operator==(const NumQueues& other) const noexcept = default;
};
static_assert(sizeof(NumQueues) == sizeof(uint32_t));

// Get/set features payload for the volatile write cache
struct [[maybe_unused]] VolatileWriteCacheConfig {
  bool volatile_write_cache_enable : 1;
  uint32_t reserved : 31;

  bool operator==(const VolatileWriteCacheConfig& other) const noexcept =
      default;
};
static_assert(sizeof(VolatileWriteCacheConfig) == sizeof(uint32_t));

// Get/set features payload for Arbitration
struct [[maybe_unused]] ArbitrationFeature {
  uint8_t arbitration_burst : 3;
  uint8_t reserved : 5;
  uint8_t low_priority_weight;
  uint8_t medium_priority_weight;
  uint8_t high_priority_weight;

  bool operator==(const ArbitrationFeature& other) const noexcept = default;
};
static_assert(sizeof(ArbitrationFeature) == sizeof(uint32_t));

// Get/Set Feature payload for Power Management
struct [[maybe_unused]] PowerMgmtFeature {
  uint8_t power_state : 5;
  uint8_t workload_hint : 3;
  uint32_t reserved : 24;

  bool operator==(const PowerMgmtFeature& other) const noexcept = default;
};
static_assert(sizeof(PowerMgmtFeature) == sizeof(uint32_t));

struct [[maybe_unused]] TempThresholdFeature {
  uint16_t temp_threshold;
  uint8_t threshold_temp_select : 4;
  uint8_t threshold_type_select : 2;
  uint16_t reserved : 10;

  bool operator==(const TempThresholdFeature& other) const noexcept = default;
};
static_assert(sizeof(TempThresholdFeature) == sizeof(uint32_t));

struct [[maybe_unused]] ErrorRecoveryFeature {
  uint16_t time_limited_error_recovery;
  // Deallocated or Unwritten Logical Block Error Enable
  uint16_t dulbe : 1;
  uint16_t reserved : 15;

  bool operator==(const ErrorRecoveryFeature& other) const noexcept = default;
};
static_assert(sizeof(ErrorRecoveryFeature) == sizeof(uint32_t));

struct [[maybe_unused]] InterruptCoalescingFeature {
  uint8_t aggregation_threshold;
  uint8_t aggregation_time;
  uint16_t reserved;

  bool operator==(const InterruptCoalescingFeature& other) const noexcept =
      default;
};
static_assert(sizeof(InterruptCoalescingFeature) == sizeof(uint32_t));

struct [[maybe_unused]] InterruptVectorConfigFeature {
  uint16_t interrupt_vector;
  bool coalescing_disable : 1;
  uint16_t reserved : 15;

  bool operator==(const InterruptVectorConfigFeature& other) const noexcept =
      default;
};
static_assert(sizeof(InterruptVectorConfigFeature) == sizeof(uint32_t));

struct WriteAtomicityFeature {
  bool disable_normal : 1;
  uint32_t reserved : 31;

  bool operator==(const WriteAtomicityFeature& other) const noexcept = default;
};
static_assert(sizeof(WriteAtomicityFeature) == sizeof(uint32_t));

// The Parameter Error Location field of an Error Information Log Entry.
struct [[maybe_unused]] ParameterErrorLocation {
  // Byte in command that contained the error. Valid values are 0 to 63.
  uint16_t byte_offset : 8;
  // Bit in command that contained the error.Valid values are 0 to 7.
  uint16_t bit_offset : 3;
  uint16_t reserved : 5;  // (reserved)

  bool operator==(const ParameterErrorLocation& other) const noexcept = default;
};
static_assert(sizeof(ParameterErrorLocation) == sizeof(uint16_t));

// A error information log entry, as returned by Get Log Page command.
// See NVMe spec 1.4 section 5.14.1.1 figure 193.
struct [[maybe_unused]] ErrorInformationLogEntry {
  // This is a 64-bit incrementing error count, indicating a unique identifier
  // for this error. The error count starts at 1h, is incremented for each
  // unique error log entry, and is retained across power off conditions. A
  // value of 0h indicates an invalid entry; this value is used when there are
  // lost entries or when there are fewer errors than the maximum number of
  // entries the controller supports.
  uint64_t error_count;
  // This field indicates the Submission Queue Identifier of the command that
  // the error information is associated with. If the error is not specific to
  // a particular command then this field shall be set to FFFFh.
  uint16_t submission_queue_id;
  // This field indicates the Command Identifier of the command that the error
  // is associated with. If the error is not specific to a particular command,
  // then this field shall be set to FFFFh.
  uint16_t command_id;
  // This field indicates the Status Field for the command that completed. The
  // Status Field is located in bits 15:01, bit 00 corresponds to the Phase Tag
  // posted for the command. If the error is not specific to a particular
  // command, then this field reports the most applicable status value.
  StatusStructure status_field;
  // This field indicates the byte and bit of the command parameter that the
  // error is associated with, if applicable. If the parameter spans multiple
  // bytes or bits, then the location indicates the first byte and bit of the
  // parameter.
  ParameterErrorLocation parameter_error_location;
  // This field indicates the first LBA that experienced the error condition,
  // if applicable
  uint64_t lba;
  // This field indicates the namespace that the error is associated with,
  // if applicable.
  uint32_t namespace_id;
  // If there is additional vendor specific error information available, this
  // field provides the log page identifier associated with that page. A value
  // of 00h indicates that no additional information is available. Valid values
  // are in the range of 80h to FF.
  uint8_t vendor_specific_information;
  // Transport Type (TRTYPE): This field indicates the Transport Type of the
  // transport associated with the error. The values in this field are the same
  // as the TRTYPE values in the Discovery Log Page Entry (refer to the NVMe
  // over Fabrics specification). If the error is not transport related, this
  // field shall be cleared to 0h. If the error is transport related, this field
  // shall be set to the type of the transport as follows:
  //   0h : The transport type is not indicated or the error is not transport
  //        related.
  //   1h : RDMA Transport (refer to the NVMe over Fabric specification).
  //   2h : Fibre Channel Transport (refer to INCITS 540).
  //   3h : TCP Transport (refer to the NVMe over Fabrics specification).
  //  FEh : Intra-host Transport (i.e., loopback) (Note: This is a reserved
  //        value for use by host software).
  // All other values are reserved.
  uint8_t transport_type;
  uint8_t reserved1[2];  // (reserved)
  // This field contains command specific information. If used, the command
  // definition specifies the information returned.
  uint64_t command_specific_information;
  // Transport Type Specific Information: This field indicates additional
  // transport type specific error information. If multiple errors exist, then
  // this field indicates additional information about the first error.  This
  // field is transport type dependent (see TRTYPE) as follows, if TRTYPE is:
  //   3h : This field indicates, the offset, in bytes, from the start of the
  //        Transport Header to the start of the field that is in error. If
  //        multiple errors exist, then this field indicates the lowest offset
  //        that is in error.
  // For all other TRTYPE values this field is reserved.
  uint16_t transport_specific_information;
  uint8_t reserved2[22];  // (reserved)

  bool operator==(const ErrorInformationLogEntry& other) const noexcept =
      default;
};
static_assert(sizeof(ErrorInformationLogEntry) == 64);

struct [[maybe_unused]] ReadWriteCdw12 {
  uint16_t number_of_logical_blocks;
  uint16_t reserved : 10;
  uint8_t protection_information_field : 4;
  bool force_unit_access : 1;
  bool limited_retry : 1;

  bool operator==(const ReadWriteCdw12& other) const noexcept = default;
};
static_assert(sizeof(ReadWriteCdw12) == sizeof(uint32_t));

static inline bool IsVendorSpecificOpcode(nvme_abi::NvmeOpcode opcode) {
  // Opcodes above 0xC0 indicate a vendor specific admin command.
  return static_cast<uint8_t>(opcode) >= 0xC0;
}

}  // namespace nvme_abi

#endif  // NVME_ABI_H_
