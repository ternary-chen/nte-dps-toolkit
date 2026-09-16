#pragma once
#include "nte/loader/Injection/ShimProtocol.h"
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace nte::loader {
// Inspect resource bytes without writing, mapping or executing the embedded DLL.
// The signature must be exported data in a bounded x64 PE, not arbitrary text.
inline bool EmbeddedShimProtocolMatches(const void* raw, std::size_t size) {
    if (!raw || size < sizeof(IMAGE_DOS_HEADER) || size > 64u * 1024u * 1024u) return false;
    const auto* bytes = static_cast<const std::uint8_t*>(raw);
    const auto fits = [size](std::size_t offset, std::size_t length) {
        return offset <= size && length <= size - offset;
    };
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, bytes, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        !fits(static_cast<std::size_t>(dos.e_lfanew), sizeof(IMAGE_NT_HEADERS64))) return false;
    IMAGE_NT_HEADERS64 nt{};
    std::memcpy(&nt, bytes + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        !(nt.FileHeader.Characteristics & IMAGE_FILE_DLL) ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT ||
        !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections > 96) return false;
    const std::size_t sectionOffset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!fits(sectionOffset, sizeof(IMAGE_SECTION_HEADER) * nt.FileHeader.NumberOfSections)) return false;
    const auto at = [&](DWORD rva, std::size_t length) -> const std::uint8_t* {
        if (rva < nt.OptionalHeader.SizeOfHeaders &&
            length <= nt.OptionalHeader.SizeOfHeaders - rva && fits(rva, length)) return bytes + rva;
        for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER section{};
            std::memcpy(&section, bytes + sectionOffset + sizeof(section) * i, sizeof(section));
            if (rva < section.VirtualAddress) continue;
            const DWORD delta = rva - section.VirtualAddress;
            if (delta <= section.SizeOfRawData && length <= section.SizeOfRawData - delta) {
                const auto offset = static_cast<std::size_t>(section.PointerToRawData) + delta;
                return fits(offset, length) ? bytes + offset : nullptr;
            }
        }
        return nullptr;
    };
    const auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto* exportBytes = at(directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || !exportBytes) return false;
    IMAGE_EXPORT_DIRECTORY exports{};
    std::memcpy(&exports, exportBytes, sizeof(exports));
    if (!exports.NumberOfNames || exports.NumberOfNames > 4096 ||
        !exports.NumberOfFunctions || exports.NumberOfFunctions > 65536) return false;
    const auto* names = at(exports.AddressOfNames, exports.NumberOfNames * sizeof(DWORD));
    const auto* ordinals = at(exports.AddressOfNameOrdinals, exports.NumberOfNames * sizeof(WORD));
    const auto* functions = at(exports.AddressOfFunctions, exports.NumberOfFunctions * sizeof(DWORD));
    if (!names || !ordinals || !functions) return false;
    for (DWORD i = 0; i < exports.NumberOfNames; ++i) {
        DWORD nameRva = 0;
        std::memcpy(&nameRva, names + i * sizeof(DWORD), sizeof(nameRva));
        const auto* name = at(nameRva, sizeof(kShimProtocolExport));
        if (!name || std::memcmp(name, kShimProtocolExport, sizeof(kShimProtocolExport)) != 0) continue;
        WORD ordinal = 0;
        std::memcpy(&ordinal, ordinals + i * sizeof(WORD), sizeof(ordinal));
        if (ordinal >= exports.NumberOfFunctions) return false;
        DWORD signatureRva = 0;
        std::memcpy(&signatureRva, functions + ordinal * sizeof(DWORD), sizeof(signatureRva));
        // A forwarded export is not the shim's own protocol declaration.
        if (signatureRva >= directory.VirtualAddress && signatureRva - directory.VirtualAddress < directory.Size)
            return false;
        const auto* signature = at(signatureRva, sizeof(kShimProtocolSignature));
        return signature && std::memcmp(signature, kShimProtocolSignature, sizeof(kShimProtocolSignature)) == 0;
    }
    return false;
}

inline bool ExecutableHasCompatibleShim() {
    const HMODULE module = GetModuleHandleW(nullptr);
    const HRSRC info = FindResourceW(module, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(10));
    if (!info) return false;
    const HGLOBAL resource = LoadResource(module, info);
    return resource && EmbeddedShimProtocolMatches(LockResource(resource), SizeofResource(module, info));
}

inline const char* LoaderCapabilitiesJson(bool compatible) {
    return compatible
        ? "{\"schema_version\":1,\"component\":\"nte-mod-loader\",\"shim_protocol_version\":3,\"embedded_shim_compatible\":true,\"payload_load_modes\":[\"manualmap\",\"loadlibrary\"],\"payload_kinds\":[\"nte_capture_runtime_v1\"],\"managed_session\":true}"
        : "{\"schema_version\":1,\"component\":\"nte-mod-loader\",\"shim_protocol_version\":3,\"embedded_shim_compatible\":false,\"payload_load_modes\":[],\"payload_kinds\":[],\"managed_session\":true,\"error_code\":\"embedded_shim_protocol_mismatch\"}";
}
}
