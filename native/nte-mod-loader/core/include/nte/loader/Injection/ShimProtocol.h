#pragma once
#include <cstddef>
#include <cstdint>

// A semantic compatibility declaration, not a binary identity or trust signature.
// Bump when the mirrored initialization layout or payload mode meaning changes.
#define NTE_LOADER_SHIM_PROTOCOL_SIGNATURE "NTE_LOADER_SHIM_ABI_V3;init=1056;manualmap=1;loadlibrary=1;nte_capture_runtime_v1=1"
namespace nte::loader {
inline constexpr std::uint32_t kShimProtocolVersion = 3;
inline constexpr std::size_t kShimInitParamsSize = 1056;
inline constexpr char kShimProtocolExport[] = "NteLoaderShimProtocol";
inline constexpr char kShimProtocolSignature[] = NTE_LOADER_SHIM_PROTOCOL_SIGNATURE;
}
