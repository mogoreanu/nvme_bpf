#include "nvme_strings.h"

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>

#include "nvme_abi.h"

namespace nvme_abi {

std::string_view NvmeIoOpcodeToString(const NvmeOpcode opcode) {
  switch (opcode) {
    case NvmeOpcode::kFlush:
      return "Flush";
    case NvmeOpcode::kWrite:
      return "Write";
    case NvmeOpcode::kRead:
      return "Read";
    case NvmeOpcode::kWriteUncorrectable:
      return "WriteUncorrectable";
    case NvmeOpcode::kCompare:
      return "Compare";
    case NvmeOpcode::kWriteZeros:
      return "WriteZeros";
    case NvmeOpcode::kDatasetMgmt:
      return "DatasetMgmt";
    case NvmeOpcode::kVerify:
      return "Verify";
    case NvmeOpcode::kReservationRegister:
      return "ReservationRegister";
    case NvmeOpcode::kReservationReport:
      return "ReservationReport";
    case NvmeOpcode::kReservationAcquire:
      return "ReservationAcquire";
    case NvmeOpcode::kReservationRelease:
      return "ReservationRelease";
    default:
      return "UnknownIoOp";
  }
}

std::string_view NvmeAdminOpcodeToString(const NvmeOpcode opcode) {
  switch (opcode) {
    case NvmeOpcode::kDeleteSubQueue:
      return "DeleteSubQueue";
    case NvmeOpcode::kCreateSubQueue:
      return "CreateSubQueue";
    case NvmeOpcode::kGetLogPage:
      return "GetLogPage";
    case NvmeOpcode::kDeleteCompQueue:
      return "DeleteCompQueue";
    case NvmeOpcode::kCreateCompQueue:
      return "CreateCompQueue";
    case NvmeOpcode::kIdentify:
      return "Identify";
    case NvmeOpcode::kAbort:
      return "Abort";
    case NvmeOpcode::kSetFeatures:
      return "SetFeatures";
    case NvmeOpcode::kGetFeatures:
      return "GetFeatures";
    case NvmeOpcode::kAsyncEventReq:
      return "AsyncEventReq";
    case NvmeOpcode::kNamespaceManagement:
      return "NamespaceManagement";
    case NvmeOpcode::kFirmwareActivate:
      return "FirmwareActivate";
    case NvmeOpcode::kFirmwareImgDownload:
      return "FirmwareImgDownload";
    case NvmeOpcode::kDeviceSelfTest:
      return "DeviceSelfTest";
    case NvmeOpcode::kNamespaceAttachment:
      return "NamespaceAttachment";
    case NvmeOpcode::kKeepAlive:
      return "KeepAlive";
    case NvmeOpcode::kDirectiveSend:
      return "DirectiveSend";
    case NvmeOpcode::kDirectiveReceive:
      return "DirectiveReceive";
    case NvmeOpcode::kVirtualizationManagement:
      return "VirtualizationManagement";
    case NvmeOpcode::kNVMeMISend:
      return "NVMeMISend";
    case NvmeOpcode::kNVMeMIReceive:
      return "NVMeMIReceive";
    case NvmeOpcode::kDoorbellMemory:
      return "DoorbellMemory";
    default:
      return "UnknownAdminOp";
  }
}


std::string_view NvmeIdentifyTypeToString(const IdentifyType id_type) {
  switch (id_type) {
    case IdentifyType::kNamespace:
      return "IdentifyNamespace";
    case IdentifyType::kController:
      return "IdentifyController";
    case IdentifyType::kActiveNsIDList:
      return "IdentifyActiveNsIDList";
    case IdentifyType::kNsIdDescList:
      return "IdentifyNsIdDescList";
    case IdentifyType::kNvmSetList:
      return "IdentifyNvmSetList";
    case IdentifyType::kAllocatedNsIdList:
      return "IdentifyAllocatedNsIdList";
    case IdentifyType::kNsByAllocatedNsId:
      return "IdentifyNsByAllocatedNsId";
    case IdentifyType::kAttachedCtrlsForNsId:
      return "IdentifyAttachedCtrlsForNsId";
    case IdentifyType::kExistingCtrlList:
      return "IdentifyExistingCtrlList";
    case IdentifyType::kPrimaryCtrlCapabilities:
      return "IdentifyPrimaryCtrlCapabilities";
    case IdentifyType::kSecondaryCtrlList:
      return "IdentifySecondaryCtrlList";
    case IdentifyType::kNsGranularityList:
      return "IdentifyNsGranularityList";
    case IdentifyType::kUuidList:
      return "IdentifyUuidList";
  }
  return "IdentifyUnknown";
}

std::string_view NvmeGenericStatusCodeToString(const StatusCode status_code) {
  switch (status_code) {
    case StatusCode::kSuccess:
      return "GENERIC_STATUS_SUCCESS";
    case StatusCode::kInvalidOpcode:
      return "GENERIC_STATUS_INVALID_OPCODE";
    case StatusCode::kInvalidField:
      return "GENERIC_STATUS_INVALID_FIELD";
    case StatusCode::kCommandIdConflict:
      return "GENERIC_STATUS_COMMAND_ID_CONFLICT";
    case StatusCode::kDataTransferError:
      return "GENERIC_STATUS_DATA_TRANSFER_ERROR";
    case StatusCode::kAbortedPowerLoss:
      return "GENERIC_STATUS_ABORTED_POWER_LOSS";
    case StatusCode::kInternalError:
      return "GENERIC_STATUS_INTERNAL_ERROR";
    case StatusCode::kAbortedByRequest:
      return "GENERIC_STATUS_ABORTED_REQ";
    case StatusCode::kAbortedSqDeletion:
      return "GENERIC_STATUS_ABORTED_SQDEL";
    case StatusCode::kAbortedFailedFused:
      return "GENERIC_STATUS_ABORTED_FAILED_FUSED";
    case StatusCode::kAbortedMissingFused:
      return "GENERIC_STATUS_ABORTED_MISSING_FUSED";
    case StatusCode::kInvalidNamespace:
      return "GENERIC_STATUS_INVALID_NAMESPACE";
    case StatusCode::kCommandSeqError:
      return "GENERIC_STATUS_COMMAND_SEQ_ERROR";
    case StatusCode::kInvalidSglDesc:
      return "GENERIC_STATUS_INVALID_SGL_DESC";
    case StatusCode::kInvalidNumOfSglDesc:
      return "GENERIC_STATUS_INVALID_NUM_OF_SGL_DESC";
    case StatusCode::kInvalidSglDataLength:
      return "GENERIC_STATUS_INVALID_SGL_DATA_LENGTH";
    case StatusCode::kInvalidSglMetadataLength:
      return "GENERIC_STATUS_INVALID_SGLMETADATA_LENGTH";
    case StatusCode::kInvalidSglDescType:
      return "GENERIC_STATUS_INVALID_SGL_DESC_TYPE";
    case StatusCode::kInvalidUseCtrlMemBuff:
      return "GENERIC_STATUS_INVALID_USE_CTRL_MEMBUFF";
    case StatusCode::kInvalidPrpOffset:
      return "GENERIC_STATUS_INVALID_PRP_OFFSET";
    case StatusCode::kAtomicWriteUnitExceeded:
      return "GENERIC_STATUS_ATOMIC_WRITE_UNIT_EXCEEDED";
    case StatusCode::kOpDenied:
      return "GENERIC_STATUS_OP_DENIED";
    case StatusCode::kInvalidSglOffset:
      return "GENERIC_STATUS_INVALID_SGL_OFFSET";
    case StatusCode::kHostIdInconsistentFormat:
      return "GENERIC_STATUS_HOST_ID_INCONSISTENT_FORMAT";
    case StatusCode::kKeepAliveTimerExpired:
      return "GENERIC_STATUS_KEEP_ALIVE_TIMER_EXPIRED";
    case StatusCode::kInvalidKeepAliveTimeout:
      return "GENERIC_STATUS_INVALID_KEEP_ALIVE_TIMEOUT";
    case StatusCode::kAbortedDuePreemptAbort:
      return "GENERIC_STATUS_ABORTED_DUE_PREEMPT_ABORT";
    case StatusCode::kSanitizeFailed:
      return "GENERIC_STATUS_SANITIZE_FAILED";
    case StatusCode::kSanitizeInProgress:
      return "GENERIC_STATUS_SANITIZE_IN_PROGRESS";
    case StatusCode::kInvalidSglDataBlckGranularity:
      return "GENERIC_STATUS_INVALID_SGL_DATA_BLCK_GRANULARITY";
    case StatusCode::kNotSupportedForQueueInCMB:
      return "GENERIC_STATUS_NOT_SUPPORTED_FOR_QUEUE_IN_CMB";
    case StatusCode::kNamespaceIsWriteProtected:
      return "GENERIC_STATUS_NAMESPACE_IS_WRITE_PROTECTED";
    case StatusCode::kCommandInterrupted:
      return "GENERIC_STATUS_COMMAND_INTERRUPTED";
    case StatusCode::kTransientTransportError:
      return "GENERIC_STATUS_TRANSIENT_TRANSPORT_ERROR";
    case StatusCode::kLbaOutOfRange:
      return "GENERIC_STATUS_LBA_OUT_OF_RANGE";
    case StatusCode::kCapacity_exceeded:
      return "GENERIC_STATUS_CAPACITY_EXCEEDED";
    case StatusCode::kNamespaceNotReady:
      return "GENERIC_STATUS_NAMESPACE_NOT_READY";
    case StatusCode::kReservationConflict:
      return "GENERIC_STATUS_RESERVATION_CONFLICT";
    case StatusCode::kFormatInProgress:
      return "GENERIC_STATUS_FORMAT_IN_PROGRESS";
    default:
      return "GENERIC_STATUS_UNKNOWN";
  }
}

std::string_view NvmeCmdSpecificStatusCodeToString(
    const StatusCode status_code) {
  switch (status_code) {
    case StatusCode::kCompletionQueueInvalid:
      return "COMMAND_SPECIFIC_STATUS_COMPLETION_QUEUE_INVALID";
    case StatusCode::kInvalidQueueId:
      return "COMMAND_SPECIFIC_STATUS_INVALID_QUEUE_ID";
    case StatusCode::kInvalidQueueSize:
      return "COMMAND_SPECIFIC_STATUS_MAX_QUEUE_SIZE_EXCEEDED";
    case StatusCode::kAbortCommandLimitExceeded:
      return "COMMAND_SPECIFIC_STATUS_ABORT_COMMAND_LIMIT_EXCEEDED";
    case StatusCode::kAsyncEventRequestLimitExceeded:
      return "COMMAND_SPECIFIC_ASYNC_EVENT_REQUEST_LIMIT_EXCEEDED";
    case StatusCode::kInvalidFirmwareSlot:
      return "COMMAND_SPECIFIC_INVALID_FIRMWARE_SLOT";
    case StatusCode::kInvalidFirmwareImage:
      return "COMMAND_SPECIFIC_INVALID_FIRMWARE_IMAGE";
    case StatusCode::kInvalidInterruptVector:
      return "COMMAND_SPECIFIC_STATUS_INVALID_INTERRUPT_VECTOR";
    case StatusCode::kInvalidLogPage:
      return "COMMAND_SPECIFIC_STATUS_INVALID_LOG_PAGE";
    case StatusCode::kInvalidFormat:
      return "COMMAND_SPECIFIC_STATUS_INVALID_FORMAT";
    case StatusCode::kFwActivationReqConventionalReset:
      return "COMMAND_SPECIFIC_FW_ACTIVATION_REQ_CONVENTIONAL_RESET";
    case StatusCode::kInvalidQueueDeletion:
      return "COMMAND_SPECIFIC_STATUS_INVALID_QUEUE_DELETION";
    case StatusCode::kFeatureIdentifierNotSaveable:
      return "COMMAND_SPECIFIC_FEATURE_IDENTIFIER_NOT_SAVEABLE";
    case StatusCode::kFeatureNotChangeable:
      return "COMMAND_SPECIFIC_FEATURE_NOT_CHANGEABLE";
    case StatusCode::kFeatureNotNamespaceSpecific:
      return "COMMAND_SPECIFIC_FEATURE_NOT_NAMESPACE_SPECIFIC";
    case StatusCode::kFwActivationReqNVMReset:
      return "COMMAND_SPECIFIC_FW_ACTIVATION_REQNVM_RESET";
    case StatusCode::kFwActivationReqCtrlLevelReset:
      return "COMMAND_SPECIFIC_FW_ACTIVATION_REQ_CTRL_LEVEL_RESET";
    case StatusCode::kFwActivationReqMaxTimeViolation:
      return "COMMAND_SPECIFIC_FW_ACTIVATION_REQ_MAX_TIME_VIOLATION";
    case StatusCode::kFwActivationProhibited:
      return "COMMAND_SPECIFIC_FW_ACTIVATION_PROHIBITED";
    case StatusCode::kOverlappingRangeFirmwareCommit:
      return "COMMAND_SPECIFIC_OVERLAPPING_RANGE_FIRMWARE_COMMIT";
    case StatusCode::kNsInsufficientCapacity:
      return "COMMAND_SPECIFIC_NS_INSUFFICIENT_CAPACITY";
    case StatusCode::kNsIdentifierUnavailable:
      return "COMMAND_SPECIFIC_NS_IDENTIFIER_UNAVAILABLE";
    case StatusCode::kNsAlreadyAttached:
      return "COMMAND_SPECIFIC_NS_ALREADY_ATTACHED";
    case StatusCode::kNsIsPrivate:
      return "COMMAND_SPECIFIC_NS_IS_PRIVATE";
    case StatusCode::kNsNotAttached:
      return "COMMAND_SPECIFIC_NS_NOT_ATTACHED";
    case StatusCode::kThinProvisioningNotSupported:
      return "COMMAND_SPECIFIC_THIN_PROVISIONING_NOT_SUPPORTED";
    case StatusCode::kControllerListInvalid:
      return "COMMAND_SPECIFIC_CONTROLLER_LIST_INVALID";
    case StatusCode::kDeviceSelfTestInProgress:
      return "COMMAND_SPECIFIC_DEVICE_SELF_TEST_IN_PROGRESS";
    case StatusCode::kBootPartitionWriteProhibited:
      return "COMMAND_SPECIFIC_BOOT_PARTITION_WRITE_PROHIBITED";
    case StatusCode::kInvalidControllerIdentifier:
      return "COMMAND_SPECIFIC_INVALID_CONTROLLER_IDENTIFIER";
    case StatusCode::kInvalidSecondaryControllerState:
      return "COMMAND_SPECIFIC_INVALID_SECONDARY_CONTROLLER_STATE";
    case StatusCode::kInvalidNumCtrlResources:
      return "COMMAND_SPECIFIC_INVALID_NUM_CTRL_RESOURCES";
    case StatusCode::kInvalidResourceIdentifier:
      return "COMMAND_SPECIFIC_INVALID_RESOURCE_IDENTIFIER";
    case StatusCode::kSanitizeProhibitedWithPMR:
      return "COMMAND_SPECIFIC_SANITIZE_PROHIBITED_WITHPMR";
    case StatusCode::kANAGroupIdentifierInvalid:
      return "COMMAND_SPECIFIC_ANA_GROUP_IDENTIFIER_INVALID";
    case StatusCode::kANAAttachFailed:
      return "COMMAND_SPECIFIC_ANA_ATTACH_FAILED";
    case StatusCode::kInvalidControllerDataQueue:
      return "COMMAND_SPECIFIC_INVALID_CONTROLLER_DATA_QUEUE";
    case StatusCode::kConflictingAttributes:
      return "COMMAND_SPECIFIC_STATUS_CONFLICTING_ATTRIBUTES";
    case StatusCode::kInvalidProtectionInformation:
      return "COMMAND_SPECIFIC_INVALID_PROTECTION_INFORMATION";
    case StatusCode::kAttemptedWriteToReadOnlyRange:
      return "COMMAND_SPECIFIC_STATUS_ATTEMPTED_WRITE_TO_RO_RANGE";
    case StatusCode::kControllerNotSuspended:
      return "COMMAND_SPECIFIC_STATUS_CONTROLLER_NOT_SUSPENDED";
    default:
      return "COMMAND_SPECIFIC_STATUS_UNKNOWN";
  }
}

std::string_view NvmeMediaErrorStatusCodeToString(
    const StatusCode status_code) {
  switch (status_code) {
    case StatusCode::kWriteFault:
      return "MEDIA_ERROR_STATUS_WRITE_FAULT";
    case StatusCode::kUnrecoveredReadError:
      return "MEDIA_ERROR_STATUS_READ_ERROR";
    case StatusCode::kE2EGuardCheckError:
      return "MEDIA_ERROR_E2E_GUARD_CHECK_ERROR";
    case StatusCode::kE2EAppTagCheckError:
      return "MEDIA_ERROR_E2E_APP_TAG_CHECK_ERROR";
    case StatusCode::kE2EReferenceTagCheckError:
      return "MEDIA_ERROR_E2E_REFERENCE_TAG_CHECK_ERROR";
    case StatusCode::kCompareFailure:
      return "MEDIA_ERROR_COMPARE_FAILURE";
    case StatusCode::kAccessDenied:
      return "MEDIA_ERROR_STATUS_ACCESS_DENIED";
    case StatusCode::kDeallocOrUnwrittenLogicalBlck:
      return "MEDIA_ERROR_DEALLOC_OR_UNWRITTEN_LOGICAL_BLCK";
    default:
      return "MEDIA_ERROR_STATUS_UNKNOWN";
  }
}

std::string_view NvmePathErrorStatusCodeToString(
    const StatusCode status_code) {
  switch (status_code) {
    case StatusCode::kInternalPathError:
      return "PATH_RELATED_INTERNAL_PATH_ERROR";
    case StatusCode::kAsymmetricAccessPersistentLoss:
      return "PATH_RELATED_ASYMMETRIC_ACCESS_PERSISTENT_LOSS";
    case StatusCode::kAsymmetricAccessInaccessible:
      return "PATH_RELATED_ASYMMETRIC_ACCESS_INACCESSIBLE";
    case StatusCode::kAsymmetricAccessTransition:
      return "PATH_RELATED_ASYMMETRIC_ACCESS_TRANSITION";
    case StatusCode::kControllerPathingError:
      return "PATH_RELATED_CONTROLLER_PATHING_ERROR";
    case StatusCode::kHostPathingError:
      return "PATH_RELATED_HOST_PATHING_ERROR";
    default:
      return "PATH_RELATED_STATUS_UNKNOWN";
  }
}

std::string_view NvmeStatusCodeToString(const StatusCodeType status_code_type,
                                         const StatusCode status_code) {
  switch (status_code_type) {
    case StatusCodeType::kGeneric:
      return NvmeGenericStatusCodeToString(status_code);
    case StatusCodeType::kCommandSpecific:
      return NvmeCmdSpecificStatusCodeToString(status_code);
    case StatusCodeType::kMediaError:
      return NvmeMediaErrorStatusCodeToString(status_code);
    case StatusCodeType::kPathRelated:
      return NvmePathErrorStatusCodeToString(status_code);
  }
  return "STATUS_CODE_TYPE_UNKNOWN";
}

std::ostream& operator<<(std::ostream& os, const StatusStructure& nvme_status) {
  return os << NvmeStatusCodeToString(nvme_status.status_code_type,
                                      nvme_status.status_code);
}

std::string_view NvmeAsyncInfoEvtErrorStatusToString(
    AsyncInfoEvtErrorStatus status) {
  switch (status) {
    case AsyncInfoEvtErrorStatus::kWriteToInvalidDoorbellRegister:
      return "WriteToInvalidDoorbellRegister";
    case AsyncInfoEvtErrorStatus::kInvalidDoorbellWriteValue:
      return "InvalidDoorbellWriteValue";
    case AsyncInfoEvtErrorStatus::kDiagnosticFailure:
      return "DiagnosticFailure";
    case AsyncInfoEvtErrorStatus::kPersistentInternalError:
      return "PersistentInternalError";
    case AsyncInfoEvtErrorStatus::kTransientInteranlError:
      return "TransientInteranlError";
    case AsyncInfoEvtErrorStatus::kFirmwareImageLoadError:
      return "FirmwareImageLoadError";
    default:
      return "Unknown";
  }
}

std::string_view FeatureIdentifierToString(FeatureType fid) {
  switch (fid) {
    case FeatureType::kReserved:
      return "Reserved";
    case FeatureType::kArbitration:
      return "Arbitration";
    case FeatureType::kPowerMgmt:
      return "PowerMgmt";
    case FeatureType::kLbaRangeType:
      return "LbaRangeType";
    case FeatureType::kTempThreshold:
      return "TempThreshold";
    case FeatureType::kErrorRecovery:
      return "ErrorRecovery";
    case FeatureType::kVolatileWriteCache:
      return "VolatileWriteCache";
    case FeatureType::kNumQueues:
      return "NumQueues";
    case FeatureType::kInterruptCoalescing:
      return "InterruptCoalescing";
    case FeatureType::kInterruptVectorConfig:
      return "InterruptVectorConfig";
    case FeatureType::kWriteAtomicity:
      return "WriteAtomicity";
    case FeatureType::kAsyncEventConfig:
      return "AsyncEventConfig";
    case FeatureType::kAutoPowerStateTrans:
      return "AutoPowerStateTrans";
    case FeatureType::kHostMemoryBuffer:
      return "HostMemoryBuffer";
    case FeatureType::kTimestamp:
      return "Timestamp";
    case FeatureType::kKeepAliveTimer:
      return "KeepAliveTimer";
    case FeatureType::kHostControlledThermal:
      return "HostControlledThermal";
    case FeatureType::kNonOpPowerStateCfg:
      return "NonOpPowerStateCfg";
    case FeatureType::kReadRecoveryLevelCfg:
      return "ReadRecoveryLevelCfg";
    case FeatureType::kPredictableLatencyCfg:
      return "PredictableLatencyCfg";
    case FeatureType::kPredictableLatencyWindow:
      return "PredictableLatencyWindow";
    case FeatureType::kLbaStatusInfoInterval:
      return "LbaStatusInfoInterval";
    case FeatureType::kHostBehaviorSupport:
      return "HostBehaviorSupport";
    case FeatureType::kSanitizeConfig:
      return "SanitizeConfig";
    case FeatureType::kEnduranceGrpEventCfg:
      return "EnduranceGrpEventCfg";
    case FeatureType::kSoftwareProgressMarker:
      return "SoftwareProgressMarker";
    case FeatureType::kHostIdentifier:
      return "HostIdentifier";
    case FeatureType::kReservationNotificationMask:
      return "ReservationNotificationMask";
    case FeatureType::kReservationPersistence:
      return "ReservationPersistence";
    case FeatureType::kNsWriteProtectionConfig:
      return "NsWriteProtectionConfig";
  }
  uint32_t fid_int = static_cast<uint32_t>(fid);
  if (0x19 <= fid_int && fid_int <= 0x77) {
    return "Reserved 0x19 to 0x77";
  }
  if (0x78 <= fid_int && fid_int <= 0x7F) {
    return "NVMe Management Interface";
  }
  if (0x85 <= fid_int && fid_int <= 0xBF) {
    return "Reserved 0x85 to 0xBF";
  }
  if (0xC0 <= fid_int && fid_int <= 0xFF) {
    return "Vendor specific";
  }
  return "Unknown Feature Id";
}

std::string_view LogPageIdToString(LogPageId log_page_id) {
  switch (log_page_id) {
    case LogPageId::kErrorInfo:
      return "ErrorInfo";
    case LogPageId::kSmartHealthInfo:
      return "SmartHealthInfo";
    case LogPageId::kFirmwareSlotInfo:
      return "FirmwareSlotInfo";
    case LogPageId::kChangedNamespaceList:
      return "ChangedNamespaceList";
    case LogPageId::kCmdsSupportedAndEffects:
      return "CmdsSupportedAndEffects";
    case LogPageId::kDeviceSelfTest:
      return "DeviceSelfTest";
    case LogPageId::kTelemetryHostInitiated:
      return "TelemetryHostInitiated";
    case LogPageId::kTelemetryCtrlInitiated:
      return "TelemetryCtrlInitiated";
    case LogPageId::kEnduranceGrpInfo:
      return "EnduranceGrpInfo";
    case LogPageId::kPredictableLatPerNvmSet:
      return "PredictableLatPerNvmSet";
    case LogPageId::kPredictableLatEvtAggr:
      return "PredictableLatEvtAggr";
    case LogPageId::kAsymmNmspAccess:
      return "AsymmNmspAccess";
    case LogPageId::kPersistentEvtLog:
      return "PersistentEvtLog";
    case LogPageId::kLbaStatusInfo:
      return "LbaStatusInfo";
    case LogPageId::kEnduranceGrpEvtAggr:
      return "EnduranceGrpEvtAggr";
    case LogPageId::kDiscovery:
      return "Discovery";
    case LogPageId::kReservationNotification:
      return "ReservationNotification";
    case LogPageId::kSanitizeStatus:
      return "SanitizeStatus";
  }
  return "Unknown Log Page Id";
}

}  // namespace nvme_abi