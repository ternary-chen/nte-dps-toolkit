#include "nte/loader/App/LoaderApp.h"
#include "nte/loader/Config/LoaderConfig.h"
#include "nte/loader/App/LoaderCapabilities.h"

#include <Windows.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

int wmain(int argc, wchar_t* argv[]) {
    // First, side-effect-free query. --dry-run --once may accompany this for
    // safe probing of old executables that ignore unknown options.
    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--capabilities-json") {
            const bool compatible = nte::loader::ExecutableHasCompatibleShim();
            std::cout << nte::loader::LoaderCapabilitiesJson(compatible) << "\n";
            return compatible ? 0 : 3;
        }
    }
    std::vector<std::wstring> arguments;
    for (int i = 1; i < argc; ++i) {
        arguments.emplace_back(argv[i]);
    }

	std::wstring modulePath(32768, L'\0');
	const DWORD length = GetModuleFileNameW(nullptr, modulePath.data(), static_cast<DWORD>(modulePath.size()));
	if (length == 0 || length >= modulePath.size()) {
		std::wcerr << L"[ERROR] executable path lookup failed\n";
		return 2;
	}
    modulePath.resize(length);
    const auto directory = std::filesystem::path(modulePath).parent_path();
    const auto config = nte::loader::LoaderConfig::Parse(arguments, directory);
    if (config.payloadLoadLibrary && !nte::loader::ExecutableHasCompatibleShim()) {
        std::wcerr << L"[ERROR] embedded_shim_protocol_mismatch\n";
        return 3;
    }

    return nte::loader::LoaderApp{}.Run(config);
}
