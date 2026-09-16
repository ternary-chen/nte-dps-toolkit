#pragma once
#include <Windows.h>
#include <cstdint>

namespace nte::shim {
// Standard registered load only. Does not initialize or hot-reload plugins.
// Exposed separately for focused tests using a harmless fixture in the test process.
bool LoadRegisteredDll(HANDLE process, const wchar_t* absolutePath);
bool QueueRegisteredDllLoad(HANDLE process, const wchar_t* absolutePath,
                            std::uint64_t sessionNonce);
}
