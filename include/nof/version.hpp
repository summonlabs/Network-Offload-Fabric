#pragma once

#include <cstdint>
#include <string_view>

// Network Offload Fabric -- public version surface.
//
// The ABI/API version is distinct from the on-disk format version and the
// protocol version; all three are versioned independently and validated
// separately. See docs/architecture.md.
namespace nof {

inline constexpr std::uint16_t kVersionMajor = 1;
inline constexpr std::uint16_t kVersionMinor = 0;
inline constexpr std::uint16_t kVersionPatch = 0;

// Persistence format version. Bumped only for incompatible on-disk layouts.
inline constexpr std::uint32_t kStoreFormatVersion = 1;

// Wire protocol version for the framed service transport.
inline constexpr std::uint16_t kProtocolVersion = 1;

// Canonical encoding version embedded in digests and exported documents so a
// digest produced by one encoding revision can never be compared against a
// digest produced by another.
inline constexpr std::uint16_t kCanonicalEncodingVersion = 1;

inline constexpr std::string_view kProductName = "Network Offload Fabric";
inline constexpr std::string_view kProductSlug = "network-offload-fabric";

std::string_view version_string() noexcept;

}  // namespace nof
