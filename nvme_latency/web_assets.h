#ifndef NVME_BPF_WEB_ASSETS_H_
#define NVME_BPF_WEB_ASSETS_H_

#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace nvme_bpf {

struct WebAsset {
  absl::string_view path;  // URL path, e.g. "/app.js".
  absl::string_view content_type;
  absl::string_view content;
};

// The static files of the web UI (the `web/` directory), embedded in the
// binary at build time by `embed_web_assets.sh`.
absl::Span<const WebAsset> EmbeddedWebAssets();

}  // namespace nvme_bpf

#endif  // NVME_BPF_WEB_ASSETS_H_
