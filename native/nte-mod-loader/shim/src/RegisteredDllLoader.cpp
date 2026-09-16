#include "shim/RegisteredDllLoader.h"
#include "shim/DllMain.h"
#include "shim/ShimGlobals.h"

#include <TlHelp32.h>
#include <cstddef>
#include <cwchar>
#include <cstring>
#include <memory>
#include <new>
#include <string>

namespace nte::shim {
namespace {
constexpr DWORD kLoadDeadlineMs = 20000;
constexpr char kHostExport[] = "NteCombatDebugProxySignature";
constexpr char kHostSignature[] = "NTE_COMBAT_DEBUG_D3D12_PROXY_V2";
constexpr char kCaptureExport[] = "NteCaptureRuntimeSignature";
constexpr char kCaptureSignature[] = "NTE_CAPTURE_RUNTIME_V1";

// Win64 ABI: RCX/RDX/R8 = three arguments, RAX = full 64-bit result.
// Preserve RBX and provide 32-byte shadow space with 16-byte call alignment.
// Every address (including GetLastError) is resolved in the target process.
struct CallBlock {
    std::uint64_t function, arg1, arg2, arg3, result;
    DWORD error, padding;
    std::uint64_t getLastError;
    wchar_t path[kPathCapacity];
    char exportName[64];
};
static_assert(sizeof(void*) == 8);
static_assert(offsetof(CallBlock, result) == 32);
static_assert(offsetof(CallBlock, error) == 40);
static_assert(offsetof(CallBlock, getLastError) == 48);
constexpr BYTE kCallCode[] = {
    0x53,                         // push rbx
    0x48,0x83,0xec,0x20,          // sub rsp,32
    0x48,0x89,0xcb,               // mov rbx,rcx
    0x48,0x8b,0x4b,0x08,          // mov rcx,[rbx+8]
    0x48,0x8b,0x53,0x10,          // mov rdx,[rbx+16]
    0x4c,0x8b,0x43,0x18,          // mov r8,[rbx+24]
    0xff,0x13,                    // call [rbx]
    0x48,0x89,0x43,0x20,          // mov [rbx+32],rax
    0xff,0x53,0x30,               // call [rbx+48]
    0x89,0x43,0x28,               // mov [rbx+40],eax
    0x31,0xc0,                    // xor eax,eax (thread exit status only)
    0x48,0x83,0xc4,0x20,0x5b,0xc3 // add rsp,32; pop rbx; ret
};

// GetProcAddress may forward kernel32 exports into KernelBase. Resolve the
// actual containing module and its RVA; never assume equal cross-process bases.
std::uint64_t RemoteProcedure(HANDLE process, const char* name) {
    const auto local = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name);
    HMODULE owner = nullptr;
    if (!local || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(local), &owner)) return 0;
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(owner, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return 0;
    const auto offset = reinterpret_cast<std::uintptr_t>(local) -
        reinterpret_cast<std::uintptr_t>(owner);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(process));
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::uint64_t result = 0;
    if (Module32FirstW(snapshot, &entry)) do {
        if (_wcsicmp(entry.szExePath, path) == 0 && offset < entry.modBaseSize) {
            result = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr) + offset;
            break;
        }
    } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return result;
}

class RemoteCall {
public:
    explicit RemoteCall(HANDLE process, ULONGLONG deadline)
        : process_(process), deadline_(deadline) {
        data_ = VirtualAllocEx(process_, nullptr, sizeof(CallBlock),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        code_ = VirtualAllocEx(process_, nullptr, sizeof(kCallCode),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        SIZE_T written = 0;
        DWORD oldProtection = 0;
        ready_ = data_ && code_ && WriteProcessMemory(process_, code_, kCallCode,
            sizeof(kCallCode), &written) && written == sizeof(kCallCode) &&
            VirtualProtectEx(process_, code_, sizeof(kCallCode), PAGE_EXECUTE_READ,
                &oldProtection) && FlushInstructionCache(process_, code_, sizeof(kCallCode));
    }
    ~RemoteCall() {
        // A timed-out thread may still access both allocations. Do not free,
        // overwrite or retry them; process exit reclaims them.
        if (!uncertain_) {
            if (data_) VirtualFreeEx(process_, data_, 0, MEM_RELEASE);
            if (code_) VirtualFreeEx(process_, code_, 0, MEM_RELEASE);
        }
    }
    std::uint64_t Address(std::size_t offset) const {
        return reinterpret_cast<std::uintptr_t>(data_) + offset;
    }
    bool Invoke(CallBlock& block) {
        if (!ready_ || uncertain_ || GetTickCount64() >= deadline_) return false;
        SIZE_T bytes = 0;
        block.result = 0;
        block.error = 0;
        if (!WriteProcessMemory(process_, data_, &block, sizeof(block), &bytes) ||
            bytes != sizeof(block)) return false;
        HANDLE thread = CreateRemoteThread(process_, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(code_), data_, 0, nullptr);
        if (!thread) return false;
        const auto now = GetTickCount64();
        const DWORD wait = WaitForSingleObject(thread,
            now >= deadline_ ? 0 : static_cast<DWORD>(deadline_ - now));
        DWORD exitCode = STILL_ACTIVE;
        const bool exitedNormally = wait == WAIT_OBJECT_0 &&
            GetExitCodeThread(thread, &exitCode) && exitCode == 0;
        CloseHandle(thread);
        if (wait != WAIT_OBJECT_0) {
            uncertain_ = true;
            return false;
        }
        if (!exitedNormally) return false;
        return ReadProcessMemory(process_, data_, &block, sizeof(block), &bytes) &&
            bytes == sizeof(block);
    }
private:
    HANDLE process_;
    ULONGLONG deadline_;
    void* data_ = nullptr;
    void* code_ = nullptr;
    bool ready_ = false;
    bool uncertain_ = false;
};

bool RemoteSignatureMatches(HANDLE process, RemoteCall& call, CallBlock& block,
                            std::uint64_t getProc, std::uint64_t module,
                            const char* exportName, const char* expected) {
    block.function = getProc;
    block.arg1 = module;
    block.arg2 = call.Address(offsetof(CallBlock, exportName));
    block.arg3 = 0;
    strcpy_s(block.exportName, exportName);
    char signature[64]{};
    const auto size = std::strlen(expected) + 1;
    SIZE_T bytes = 0;
    return size <= sizeof(signature) && call.Invoke(block) && block.result &&
        ReadProcessMemory(process, reinterpret_cast<void*>(block.result), signature,
            size, &bytes) && bytes == size && std::memcmp(signature, expected, size) == 0;
}

bool PlatformPathMatches(HANDLE process, const std::wstring& hostPath) {
    const auto slash = hostPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    const auto expected = hostPath.substr(0, slash + 1) + L"NTE-Platform.dll";
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(process));
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Module32FirstW(snapshot, &entry)) do {
        if (_wcsicmp(entry.szModule, L"NTE-Platform.dll") == 0) {
            found = _wcsicmp(entry.szExePath, expected.c_str()) == 0;
            break;
        }
    } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return found;
}

struct LoadRequest {
    HANDLE process = nullptr;
    wchar_t path[kPathCapacity]{};
    std::uint64_t nonce = 0;
    ~LoadRequest() { if (process) CloseHandle(process); }
};

DWORD WINAPI RegisteredLoadWorker(void* parameter) {
    std::unique_ptr<LoadRequest> request(static_cast<LoadRequest*>(parameter));
    try {
        if (LoadRegisteredDll(request->process, request->path))
            WriteMarkerFile(kInternalLoadedMarkerFormat,
                GetProcessId(request->process), request->nonce);
    } catch (...) {
        // Do not let allocation/path failures escape a launcher worker.
    }
    return 0;
}
} // namespace

bool LoadRegisteredDll(HANDLE process, const wchar_t* absolutePath) {
    if (!process || !absolutePath) return false;
    wchar_t normalized[kPathCapacity]{};
    const DWORD length = GetFullPathNameW(absolutePath, kPathCapacity, normalized, nullptr);
    if (!length || length >= kPathCapacity || _wcsicmp(normalized, absolutePath) != 0)
        return false; // require a frozen absolute path, never target CWD interpretation
    const ULONGLONG deadline = GetTickCount64() + kLoadDeadlineMs;
    std::uint64_t load = 0;
    while (!(load = RemoteProcedure(process, "LoadLibraryExW"))) {
        if (GetTickCount64() >= deadline || WaitForSingleObject(process, 50) != WAIT_TIMEOUT)
            return false;
    }
    const auto modulePath = RemoteProcedure(process, "GetModuleFileNameW");
    const auto getProc = RemoteProcedure(process, "GetProcAddress");
    const auto release = RemoteProcedure(process, "FreeLibrary");
    const auto lastError = RemoteProcedure(process, "GetLastError");
    if (!modulePath || !getProc || !release || !lastError) return false;
    RemoteCall call(process, deadline);
    CallBlock block{};
    block.getLastError = lastError;
    wcscpy_s(block.path, absolutePath);
    block.function = load;
    block.arg1 = call.Address(offsetof(CallBlock, path));
    block.arg2 = 0;
    block.arg3 = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS;
    if (!call.Invoke(block) || !block.result) return false;
    const auto module = block.result;
    block.function = modulePath;
    block.arg1 = module;
    block.arg2 = call.Address(offsetof(CallBlock, path));
    block.arg3 = kPathCapacity;
    block.path[0] = L'\0';
    bool valid = call.Invoke(block) && block.result > 0 && block.result < kPathCapacity &&
        _wcsicmp(block.path, absolutePath) == 0;
    const wchar_t* basename = wcsrchr(absolutePath, L'\\');
    const bool host = basename && _wcsicmp(basename + 1, L"d3d12.dll") == 0;
    const bool capture = basename && _wcsicmp(basename + 1, L"NTE_Capture.dll") == 0;
    if (valid && host) {
        valid = RemoteSignatureMatches(process, call, block, getProc, module,
            kHostExport, kHostSignature) && PlatformPathMatches(process, absolutePath);
    } else if (valid && capture) {
        valid = RemoteSignatureMatches(process, call, block, getProc, module,
            kCaptureExport, kCaptureSignature);
    }
    if (!valid) {
        // Release only the reference acquired by this LoadLibraryExW. Never
        // unload an existing module by enumeration/name or assume a system DLL is ours.
        block.function = release;
        block.arg1 = module;
        block.arg2 = block.arg3 = 0;
        call.Invoke(block);
    }
    return valid;
}

bool QueueRegisteredDllLoad(HANDLE process, const wchar_t* absolutePath,
                            std::uint64_t sessionNonce) {
    if (!absolutePath || wcsnlen_s(absolutePath, kPathCapacity) >= kPathCapacity) return false;
    auto request = std::unique_ptr<LoadRequest>(new (std::nothrow) LoadRequest());
    if (!request || !DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(),
        &request->process, 0, FALSE, DUPLICATE_SAME_ACCESS)) return false;
    wcscpy_s(request->path, absolutePath);
    request->nonce = sessionNonce;
    HANDLE thread = CreateThread(nullptr, 0, RegisteredLoadWorker, request.get(), 0, nullptr);
    if (!thread) return false;
    request.release();
    CloseHandle(thread);
    return true;
}
} // namespace nte::shim
