#ifndef NVME_STRINGS_H_
#define NVME_STRINGS_H_

#include <cstdint>
#include <ostream>
#include <string>

#include "nvme_abi.h"

namespace nvme_abi {

std::string_view NvmeIoOpcodeToString(NvmeOpcode opcode);

std::string_view NvmeAdminOpcodeToString(NvmeOpcode opcode);

std::string_view NvmeIdentifyTypeToString(IdentifyType id_type);

std::string_view NvmeGenericStatusCodeToString(StatusCode status_code);

std::string_view NvmeCmdSpecificStatusCodeToString(StatusCode status_code);

std::string_view NvmeMediaErrorStatusCodeToString(StatusCode status_code);

std::string_view NvmePathErrorStatusCodeToString(StatusCode status_code);

std::string_view NvmeStatusCodeToString(StatusCodeType status_code_type,
                                         StatusCode status_code);

std::ostream& operator<<(std::ostream& os, const StatusStructure& nvme_status);

std::string_view NvmeAsyncInfoEvtErrorStatusToString(
    AsyncInfoEvtErrorStatus status);

std::string_view FeatureIdentifierToString(FeatureType fid);
// Alias method until we rename the FeatureType to FeatureIdentifier.
inline std::string_view FeatureTypeToString(FeatureType fid) {
  return FeatureIdentifierToString(fid);
}

std::string_view LogPageIdToString(LogPageId log_page_id);

}  // namespace nvme_abi

#endif  // NVME_STRINGS_H_