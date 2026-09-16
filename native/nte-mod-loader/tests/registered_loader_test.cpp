// 定向验证标准加载：只在测试进程加载无游戏行为的 DLL fixture。
#include "nte/loader/Config/LoaderConfig.h"
#include "nte/loader/Injection/ShimPayload.h"
#include "shim/ShimGlobals.h"
#include "shim/RegisteredDllLoader.h"
#include <Windows.h>
#include <atomic>
#include <filesystem>
#include <iostream>
#include <string>

static_assert(sizeof(nte::loader::ShimInitParams) == sizeof(nte::shim::ShimInitParams));
static_assert(offsetof(nte::loader::ShimInitParams, payloadLoadLibrary) ==
              offsetof(nte::shim::ShimInitParams, payloadLoadLibrary));
std::atomic<unsigned> markers{0};
std::atomic<DWORD> markerPid{0};
namespace nte::shim {
void WriteMarkerFile(const wchar_t*, DWORD pid, std::uint64_t nonce) {
    if (nonce == 42) { markerPid = pid; ++markers; }
}
}
int failures = 0;
#define CHECK(x) do { if (!(x)) { ++failures; std::cerr << "FAIL " #x " line " << __LINE__ << '\n'; } } while (0)

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--fixture-child") {
        HANDLE stop = OpenEventW(SYNCHRONIZE, FALSE, argv[2]);
        if (!stop) return 3;
        const DWORD waited = WaitForSingleObject(stop, 15000);
        CloseHandle(stop);
        return waited == WAIT_OBJECT_0 ? 0 : 4;
    }
    if (argc != 2) return 2;
    const auto root = std::filesystem::absolute(argv[1]);
    const auto host = root / L"host" / L"d3d12.dll";
    const auto negative = root / L"unsigned" / L"d3d12.dll";
    const auto wrongPlatform = root / L"wrong" / L"NTE-Platform.dll";
    using nte::loader::LoaderConfig;
    CHECK(!LoaderConfig::Parse({}, root).payloadLoadLibrary);
    auto standard = LoaderConfig::Parse({L"--dll", host.wstring(),
        L"--payload-load-mode", L"loadlibrary", L"--monitor-timeout", L"0",
        L"--owner-pid", L"42"}, root);
    CHECK(standard.controlArgumentsValid && standard.payloadLoadLibrary);
    CHECK(standard.payloadDll == host && standard.monitorTimeoutSeconds == 0 && standard.ownerProcessId == 42);
    CHECK(!LoaderConfig::Parse({L"--payload-load-mode", L"manualmap"}, root).payloadLoadLibrary);
    CHECK(!LoaderConfig::Parse({L"--payload-load-mode"}, root).controlArgumentsValid);
    CHECK(!LoaderConfig::Parse({L"--payload-load-mode", L"unknown"}, root).controlArgumentsValid);
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), L"relative.dll"));
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), (root/L"missing.dll").c_str()));
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), negative.c_str()));
    CHECK(GetModuleHandleW(negative.c_str()) == nullptr);

    const auto generic = root / L"unsigned" / L"generic.dll";
    CHECK(nte::shim::LoadRegisteredDll(GetCurrentProcess(), generic.c_str()));
    HMODULE genericModule = GetModuleHandleW(generic.c_str());
    if (genericModule) CHECK(FreeLibrary(genericModule));

    // New minimal runtime must carry its own public signature, with no Platform.
    const auto capture = root / L"capture" / L"NTE_Capture.dll";
    const auto oldCapture = root / L"old-capture" / L"NTE_Capture.dll";
    const auto unsignedCapture = root / L"unsigned" / L"NTE_Capture.dll";
    CHECK(GetModuleHandleW(L"NTE-Platform.dll") == nullptr);
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), oldCapture.c_str()));
    CHECK(GetModuleHandleW(oldCapture.c_str()) == nullptr);
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), unsignedCapture.c_str()));
    CHECK(GetModuleHandleW(unsignedCapture.c_str()) == nullptr);
    CHECK(nte::shim::LoadRegisteredDll(GetCurrentProcess(), capture.c_str()));
    HMODULE runtime = GetModuleHandleW(capture.c_str());
    CHECK(runtime != nullptr && GetModuleHandleW(L"NTE-Platform.dll") == nullptr);
    if (runtime) CHECK(FreeLibrary(runtime));

    // Preloaded wrong-directory dependency must not satisfy the native host layout.
    HMODULE wrong = LoadLibraryW(wrongPlatform.c_str());
    CHECK(wrong != nullptr);
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), host.c_str()));
    CHECK(GetModuleHandleW(host.c_str()) == nullptr);
    if (wrong) FreeLibrary(wrong);

    // A system d3d12 already present must not be mistaken for the payload.
    wchar_t system[MAX_PATH]{};
    CHECK(GetSystemDirectoryW(system, MAX_PATH) != 0);
    const auto systemD3D = std::filesystem::path(system)/L"d3d12.dll";
    HMODULE systemModule = LoadLibraryW(systemD3D.c_str());
    CHECK(systemModule != nullptr);
    CHECK(!nte::shim::LoadRegisteredDll(GetCurrentProcess(), systemD3D.c_str()));
    CHECK(GetModuleHandleW(systemD3D.c_str()) == systemModule);
    CHECK(nte::shim::LoadRegisteredDll(GetCurrentProcess(), host.c_str()));
    HMODULE loaded = GetModuleHandleW(host.c_str());
    CHECK(loaded != nullptr && loaded != systemModule);
    if (loaded) {
        const auto probe = reinterpret_cast<int(*)()>(GetProcAddress(loaded, "FixtureProbe"));
        CHECK(probe && probe() == 42); // dependency found beside Host, outside app directory
        CHECK(FreeLibrary(loaded));
    }
    CHECK(nte::shim::QueueRegisteredDllLoad(GetCurrentProcess(), host.c_str(), 42));
    const auto deadline = GetTickCount64() + 5000;
    while (!markers.load() && GetTickCount64() < deadline) Sleep(10);
    CHECK(markers.load() == 1);
    CHECK(markerPid.load() == GetCurrentProcessId());
    loaded = GetModuleHandleW(host.c_str());
    if (loaded) FreeLibrary(loaded);
    if (systemModule) FreeLibrary(systemModule);

    // A harmless child verifies cross-process RVA resolution/parameter pointers,
    // and that queued standard loading preserves the caller's suspended process.
    const auto eventName = L"Local\\NteRegisteredLoaderFixture-" + std::to_wstring(GetCurrentProcessId());
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, eventName.c_str());
    CHECK(stop != nullptr);
    wchar_t executable[MAX_PATH]{};
    CHECK(GetModuleFileNameW(nullptr, executable, MAX_PATH) > 0);
    auto command = std::wstring(L"\"") + executable + L"\" --fixture-child " + eventName;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const bool created = CreateProcessW(executable, command.data(), nullptr, nullptr,
        FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child) != FALSE;
    CHECK(created);
    if (created) {
        markers = 0;
        CHECK(nte::shim::QueueRegisteredDllLoad(child.hProcess, capture.c_str(), 42));
        Sleep(100);
        CHECK(markers.load() == 0);
        CHECK(ResumeThread(child.hThread) == 1);
        const auto childDeadline = GetTickCount64() + 5000;
        while (!markers.load() && GetTickCount64() < childDeadline) Sleep(10);
        CHECK(markers.load() == 1 && markerPid.load() == child.dwProcessId);
        SetEvent(stop);
        CHECK(WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0);
        DWORD exitCode = STILL_ACTIVE;
        CHECK(GetExitCodeProcess(child.hProcess, &exitCode) && exitCode == 0);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
    }
    if (stop) CloseHandle(stop);
    std::cout << (failures ? "REGISTERED_LOADER_FAILED" : "REGISTERED_LOADER_PASSED") << '\n';
    return failures ? 1 : 0;
}
