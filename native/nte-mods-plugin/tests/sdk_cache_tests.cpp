#include "../src/dumper7_sdk.hpp"
#include "../src/sdk_cache.hpp"

#include <Windows.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace nte::mods::offsets
{
	bool Initialize(void*) { return false; }
	const ResolvedOffsets* Get() { return nullptr; }
}

namespace nte::mods::dumper7
{
	bool GenerateCppSdk(
		const offsets::ResolvedOffsets&,
		const std::filesystem::path&,
		const char*,
		HANDLE,
		wchar_t*,
		size_t) noexcept
	{
		return false;
	}
}

namespace
{
	void Write(const std::filesystem::path& path, const char* text)
	{
		std::filesystem::create_directories(path.parent_path());
		std::ofstream output(path, std::ios::binary | std::ios::trunc);
		output << text;
	}

	std::string Read(const std::filesystem::path& path)
	{
		std::ifstream input(path, std::ios::binary);
		return std::string(
			std::istreambuf_iterator<char>(input),
			std::istreambuf_iterator<char>());
	}

	bool FakeGenerate(
		const nte::mods::offsets::ResolvedOffsets&,
		const std::filesystem::path& staging_root,
		const char* checksum,
		HANDLE,
		wchar_t*,
		size_t) noexcept
	{
		try
		{
			const auto sdk = staging_root / L"CppSDK";
			Write(sdk / L"SDK.hpp", "sdk");
			Write(sdk / L"PropertyFixup.hpp", "fixup");
			Write(sdk / L"UnrealContainers.hpp", "containers");
			Write(sdk / L"SDK" / L"Basic.hpp", "basic-hpp");
			Write(sdk / L"SDK" / L"Basic.cpp", "basic-cpp");
			Write(sdk / L"generation.txt", checksum);
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	bool FailGenerate(
		const nte::mods::offsets::ResolvedOffsets&,
		const std::filesystem::path&,
		const char*,
		HANDLE,
		wchar_t*,
		size_t) noexcept
	{
		return false;
	}
}

int main()
{
	namespace fs = std::filesystem;
	wchar_t name[128]{};
	swprintf_s(
		name,
		L"nte-sdk-cache-tests-%lu-%llu",
		static_cast<unsigned long>(GetCurrentProcessId()),
		static_cast<unsigned long long>(GetTickCount64()));
	const fs::path root = fs::temp_directory_path() / name;
	const fs::path plugin = root / L"plugin";
	const fs::path executable = root / L"HTGame.exe";
	fs::create_directories(plugin);
	Write(executable, "version-one");

	wchar_t error[512]{};
	nte::mods::sdk_cache::CacheContext first{};
	const auto first_inspection = nte::mods::sdk_cache::Inspect(
		executable, plugin, first, error, _countof(error));
	nte::mods::offsets::ResolvedOffsets resolved{};
	const auto first_publish = nte::mods::sdk_cache::Regenerate(
		first, resolved, &FakeGenerate, nullptr, error, _countof(error));
	nte::mods::sdk_cache::CacheContext reused{};
	const auto second_inspection = nte::mods::sdk_cache::Inspect(
		executable, plugin, reused, error, _countof(error));
	const std::string first_generation = Read(plugin / L"NTE_SDK" / L"generation.txt");
	const std::string first_checksum = Read(plugin / L"NTE_SDK.checksum");

	Write(executable, "version-two");
	nte::mods::sdk_cache::CacheContext changed{};
	const auto changed_inspection = nte::mods::sdk_cache::Inspect(
		executable, plugin, changed, error, _countof(error));
	const auto failed_publish = nte::mods::sdk_cache::Regenerate(
		changed, resolved, &FailGenerate, nullptr, error, _countof(error));
	const bool failure_preserved =
		Read(plugin / L"NTE_SDK" / L"generation.txt") == first_generation &&
		Read(plugin / L"NTE_SDK.checksum") == first_checksum;
	const auto changed_publish = nte::mods::sdk_cache::Regenerate(
		changed, resolved, &FakeGenerate, nullptr, error, _countof(error));
	nte::mods::sdk_cache::CacheContext final_context{};
	const auto final_inspection = nte::mods::sdk_cache::Inspect(
		executable, plugin, final_context, error, _countof(error));

	const bool passed =
		first_inspection == nte::mods::sdk_cache::InspectResult::RegenerationRequired &&
		first_publish == nte::mods::sdk_cache::PublishResult::Generated &&
		second_inspection == nte::mods::sdk_cache::InspectResult::Reusable &&
		changed_inspection == nte::mods::sdk_cache::InspectResult::RegenerationRequired &&
		failed_publish == nte::mods::sdk_cache::PublishResult::Error &&
		failure_preserved &&
		changed_publish == nte::mods::sdk_cache::PublishResult::Generated &&
		final_inspection == nte::mods::sdk_cache::InspectResult::Reusable &&
		Read(plugin / L"NTE_SDK" / L"generation.txt") != first_generation;
	std::printf(
		"SDK_CACHE_TEST first=regenerate second=reuse mismatch=regenerate failed_publish_preserved=%s final=reuse checksum_bytes=%zu sdk_only=true\n",
		failure_preserved ? "true" : "false",
		Read(plugin / L"NTE_SDK.checksum").size());
	std::error_code cleanup_error;
	fs::remove_all(root, cleanup_error);
	return passed ? 0 : 1;
}
