#include "sdk_cache.hpp"

#include "dumper7_sdk.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <exception>
#include <fstream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace nte::mods::sdk_cache
{
	namespace
	{
		constexpr uint64_t MAX_EXECUTABLE_BYTES = 2ULL * 1024 * 1024 * 1024;
		constexpr uintmax_t MAX_GENERATED_SDK_BYTES = 8ULL * 1024 * 1024 * 1024;
		constexpr size_t MAX_GENERATED_SDK_FILES = 100000;
		constexpr DWORD HASH_READ_CHUNK = 1024 * 1024;
		constexpr DWORD OFFSET_RETRY_MS = 1000;
		constexpr wchar_t SDK_DIRECTORY_NAME[] = L"NTE_SDK";
		constexpr wchar_t CHECKSUM_FILE_NAME[] = L"NTE_SDK.checksum";

		void SetError(
			const wchar_t* message,
			wchar_t* output,
			size_t capacity) noexcept
		{
			if (output == nullptr || capacity == 0)
				return;
			output[0] = L'\0';
			if (message == nullptr)
				return;
			size_t index = 0;
			while (index + 1 < capacity && message[index] != L'\0')
			{
				output[index] = message[index];
				++index;
			}
			output[index] = L'\0';
		}

		void SetSystemError(
			const wchar_t* operation,
			DWORD code,
			wchar_t* output,
			size_t capacity) noexcept
		{
			wchar_t buffer[256]{};
			if (swprintf_s(
					buffer,
					L"%s failed with Windows error %lu",
					operation,
					static_cast<unsigned long>(code)) < 0)
				SetError(operation, output, capacity);
			else
				SetError(buffer, output, capacity);
		}

		bool ModulePath(
			HMODULE module,
			std::filesystem::path& result,
			wchar_t* error,
			size_t error_capacity)
		{
			std::vector<wchar_t> buffer(512);
			while (buffer.size() <= 32768)
			{
				const DWORD length = GetModuleFileNameW(
					module,
					buffer.data(),
					static_cast<DWORD>(buffer.size()));
				if (length == 0)
				{
					SetSystemError(
						L"GetModuleFileNameW",
						GetLastError(),
						error,
						error_capacity);
					return false;
				}
				if (length < buffer.size() - 1)
				{
					result = std::filesystem::path(buffer.data(), buffer.data() + length);
					return true;
				}
				buffer.resize(buffer.size() * 2);
			}
			SetError(L"module path exceeds 32768 characters", error, error_capacity);
			return false;
		}

		bool ComputeSha256(
			const std::filesystem::path& path,
			std::array<uint8_t, SHA256_SIZE>& digest,
			wchar_t* error,
			size_t error_capacity)
		{
			HANDLE file = CreateFileW(
				path.c_str(),
				GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
				nullptr);
			if (file == INVALID_HANDLE_VALUE)
			{
				SetSystemError(
					L"CreateFileW(executable)",
					GetLastError(),
					error,
					error_capacity);
				return false;
			}

			LARGE_INTEGER size{};
			if (!GetFileSizeEx(file, &size))
			{
				const DWORD code = GetLastError();
				CloseHandle(file);
				SetSystemError(L"GetFileSizeEx", code, error, error_capacity);
				return false;
			}
			if (size.QuadPart <= 0 ||
				static_cast<uint64_t>(size.QuadPart) > MAX_EXECUTABLE_BYTES)
			{
				CloseHandle(file);
				SetError(L"executable size is outside the 1..2 GiB checksum budget", error, error_capacity);
				return false;
			}

			BCRYPT_ALG_HANDLE algorithm = nullptr;
			BCRYPT_HASH_HANDLE hash = nullptr;
			std::vector<uint8_t> hash_object;
			bool succeeded = false;
			do
			{
				if (BCryptOpenAlgorithmProvider(
						&algorithm,
						BCRYPT_SHA256_ALGORITHM,
						nullptr,
						0) < 0)
				{
					SetError(L"BCryptOpenAlgorithmProvider(SHA-256) failed", error, error_capacity);
					break;
				}
				DWORD object_length = 0;
				DWORD returned = 0;
				if (BCryptGetProperty(
						algorithm,
						BCRYPT_OBJECT_LENGTH,
						reinterpret_cast<PUCHAR>(&object_length),
						sizeof(object_length),
						&returned,
						0) < 0 ||
					returned != sizeof(object_length) || object_length == 0 ||
					object_length > 1024 * 1024)
				{
					SetError(L"BCrypt SHA-256 object length is invalid", error, error_capacity);
					break;
				}
				hash_object.resize(object_length);
				if (BCryptCreateHash(
						algorithm,
						&hash,
						hash_object.data(),
						static_cast<ULONG>(hash_object.size()),
						nullptr,
						0,
						0) < 0)
				{
					SetError(L"BCryptCreateHash(SHA-256) failed", error, error_capacity);
					break;
				}

				std::vector<uint8_t> buffer(HASH_READ_CHUNK);
				for (;;)
				{
					DWORD bytes_read = 0;
					if (!ReadFile(
							file,
							buffer.data(),
							static_cast<DWORD>(buffer.size()),
							&bytes_read,
							nullptr))
					{
						SetSystemError(L"ReadFile(executable)", GetLastError(), error, error_capacity);
						break;
					}
					if (bytes_read == 0)
					{
						if (BCryptFinishHash(
								hash,
								digest.data(),
								static_cast<ULONG>(digest.size()),
								0) < 0)
							SetError(L"BCryptFinishHash(SHA-256) failed", error, error_capacity);
						else
							succeeded = true;
						break;
					}
					if (BCryptHashData(hash, buffer.data(), bytes_read, 0) < 0)
					{
						SetError(L"BCryptHashData(SHA-256) failed", error, error_capacity);
						break;
					}
				}
			} while (false);

			if (hash != nullptr)
				BCryptDestroyHash(hash);
			if (algorithm != nullptr)
				BCryptCloseAlgorithmProvider(algorithm, 0);
			CloseHandle(file);
			return succeeded;
		}

		void FormatChecksum(
			const std::array<uint8_t, SHA256_SIZE>& digest,
			std::array<char, SHA256_HEX_SIZE + 1>& output) noexcept
		{
			constexpr char HEX[] = "0123456789abcdef";
			for (size_t index = 0; index < digest.size(); ++index)
			{
				output[index * 2] = HEX[digest[index] >> 4];
				output[index * 2 + 1] = HEX[digest[index] & 0x0F];
			}
			output[SHA256_HEX_SIZE] = '\0';
		}

		bool HasRequiredSdkFiles(const std::filesystem::path& sdk)
		{
			std::error_code error;
			if (std::filesystem::is_symlink(sdk, error) || error ||
				!std::filesystem::is_directory(sdk, error) || error)
				return false;
			const std::filesystem::path required[]{
				sdk / L"SDK.hpp",
				sdk / L"PropertyFixup.hpp",
				sdk / L"UnrealContainers.hpp",
				sdk / L"SDK" / L"Basic.hpp",
				sdk / L"SDK" / L"Basic.cpp",
			};
			for (const std::filesystem::path& path : required)
			{
				if (std::filesystem::is_symlink(path, error) || error ||
					!std::filesystem::is_regular_file(path, error) || error ||
					std::filesystem::file_size(path, error) == 0 || error)
					return false;
			}
			return true;
		}

		bool HasGeneratedSdkBudget(const std::filesystem::path& sdk)
		{
			std::error_code error;
			size_t count = 0;
			uintmax_t bytes = 0;
			for (std::filesystem::recursive_directory_iterator iterator(
					sdk,
					std::filesystem::directory_options::skip_permission_denied,
					error), end;
				!error && iterator != end;
				iterator.increment(error))
			{
				if (iterator->is_symlink(error) || error)
					return false;
				if (!iterator->is_regular_file(error))
				{
					if (error)
						return false;
					continue;
				}
				if (++count > MAX_GENERATED_SDK_FILES)
					return false;
				const uintmax_t size = iterator->file_size(error);
				if (error || size > MAX_GENERATED_SDK_BYTES - bytes)
					return false;
				bytes += size;
			}
			return !error && count != 0;
		}

		bool ChecksumMatches(const CacheContext& context)
		{
			std::error_code error;
			if (!std::filesystem::is_regular_file(context.checksum_file, error) || error)
				return false;
			const uintmax_t size = std::filesystem::file_size(context.checksum_file, error);
			if (error || size == 0 || size > 128)
				return false;
			std::ifstream input(context.checksum_file, std::ios::binary);
			if (!input)
				return false;
			std::array<char, 129> contents{};
			input.read(contents.data(), static_cast<std::streamsize>(size));
			if (input.gcount() != static_cast<std::streamsize>(size))
				return false;
			size_t length = static_cast<size_t>(size);
			while (length != 0 &&
				(contents[length - 1] == '\r' || contents[length - 1] == '\n'))
				--length;
			return length == SHA256_HEX_SIZE &&
				std::equal(
					contents.begin(),
					contents.begin() + SHA256_HEX_SIZE,
					context.checksum_hex.begin());
		}

		bool WriteChecksumTemp(
			const std::filesystem::path& path,
			const CacheContext& context,
			wchar_t* error,
			size_t error_capacity)
		{
			HANDLE file = CreateFileW(
				path.c_str(),
				GENERIC_WRITE,
				0,
				nullptr,
				CREATE_NEW,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);
			if (file == INVALID_HANDLE_VALUE)
			{
				SetSystemError(L"CreateFileW(checksum temp)", GetLastError(), error, error_capacity);
				return false;
			}
			std::array<char, SHA256_HEX_SIZE + 2> contents{};
			std::copy_n(
				context.checksum_hex.begin(), SHA256_HEX_SIZE, contents.begin());
			contents[SHA256_HEX_SIZE] = '\n';
			DWORD written = 0;
			const bool succeeded = WriteFile(
				file,
				contents.data(),
				static_cast<DWORD>(SHA256_HEX_SIZE + 1),
				&written,
				nullptr) &&
				written == SHA256_HEX_SIZE + 1 && FlushFileBuffers(file);
			const DWORD code = succeeded ? ERROR_SUCCESS : GetLastError();
			CloseHandle(file);
			if (!succeeded)
				SetSystemError(L"WriteFile(checksum temp)", code, error, error_capacity);
			return succeeded;
		}

		std::filesystem::path UniqueSibling(
			const std::filesystem::path& directory,
			const wchar_t* stem)
		{
			const unsigned long process_id = GetCurrentProcessId();
			const unsigned long long tick = GetTickCount64();
			wchar_t name[128]{};
			swprintf_s(
				name,
				L".%s.%lu.%llu",
				stem,
				process_id,
				tick);
			return directory / name;
		}

		bool IsDirectChild(
			const std::filesystem::path& parent,
			const std::filesystem::path& child)
		{
			return !parent.empty() && child.parent_path() == parent &&
				!child.filename().empty();
		}
	} // namespace

	InspectResult InspectImpl(
		const std::filesystem::path& executable_path,
		const std::filesystem::path& plugin_directory,
		CacheContext& context,
		wchar_t* error,
		size_t error_capacity)
	{
		context = {};
		if (error != nullptr && error_capacity != 0)
			error[0] = L'\0';
		if (executable_path.empty() || plugin_directory.empty())
		{
			SetError(L"SDK cache paths are empty", error, error_capacity);
			return InspectResult::Error;
		}
		context.executable_path = executable_path;
		context.plugin_directory = plugin_directory;
		context.sdk_directory = plugin_directory / SDK_DIRECTORY_NAME;
		context.checksum_file = plugin_directory / CHECKSUM_FILE_NAME;
		if (!ComputeSha256(
				context.executable_path,
				context.checksum,
				error,
				error_capacity))
			return InspectResult::Error;
		FormatChecksum(context.checksum, context.checksum_hex);
		return ChecksumMatches(context) && HasRequiredSdkFiles(context.sdk_directory)
			? InspectResult::Reusable
			: InspectResult::RegenerationRequired;
	}

	PublishResult RegenerateImpl(
		const CacheContext& context,
		const offsets::ResolvedOffsets& resolved,
		GenerateSdk generator,
		HANDLE stop_event,
		wchar_t* error,
		size_t error_capacity)
	{
		if (error != nullptr && error_capacity != 0)
			error[0] = L'\0';
		if (generator == nullptr ||
			!IsDirectChild(context.plugin_directory, context.sdk_directory) ||
			!IsDirectChild(context.plugin_directory, context.checksum_file))
		{
			SetError(L"SDK cache regeneration arguments are invalid", error, error_capacity);
			return PublishResult::Error;
		}
		std::error_code fs_error;
		if (!std::filesystem::is_directory(context.plugin_directory, fs_error) || fs_error)
		{
			SetError(L"plugin directory is unavailable", error, error_capacity);
			return PublishResult::Error;
		}

		const std::filesystem::path staging_root =
			UniqueSibling(context.plugin_directory, L"NTE_SDK.tmp");
		const std::filesystem::path generated_sdk = staging_root / L"CppSDK";
		const std::filesystem::path backup_sdk =
			UniqueSibling(context.plugin_directory, L"NTE_SDK.previous");
		const std::filesystem::path checksum_temp =
			UniqueSibling(context.plugin_directory, L"NTE_SDK.checksum.tmp");
		if (!std::filesystem::create_directory(staging_root, fs_error) || fs_error)
		{
			SetError(L"could not create SDK staging directory", error, error_capacity);
			return PublishResult::Error;
		}

		const bool generated = generator(
			resolved,
			staging_root,
			context.checksum_hex.data(),
			stop_event,
			error,
			error_capacity);
		if (!generated || !HasRequiredSdkFiles(generated_sdk) ||
			!HasGeneratedSdkBudget(generated_sdk))
		{
			if (generated)
				SetError(L"generated SDK is incomplete or exceeds its resource budget", error, error_capacity);
			std::filesystem::remove_all(staging_root, fs_error);
			return PublishResult::Error;
		}

		if (!WriteChecksumTemp(checksum_temp, context, error, error_capacity))
		{
			std::filesystem::remove_all(staging_root, fs_error);
			return PublishResult::Error;
		}

		const bool had_previous =
			std::filesystem::is_directory(context.sdk_directory, fs_error) && !fs_error;
		if (had_previous)
		{
			std::filesystem::rename(context.sdk_directory, backup_sdk, fs_error);
			if (fs_error)
			{
				SetError(L"could not move the previous SDK cache aside", error, error_capacity);
				std::filesystem::remove(checksum_temp, fs_error);
				std::filesystem::remove_all(staging_root, fs_error);
				return PublishResult::Error;
			}
		}

		std::filesystem::rename(generated_sdk, context.sdk_directory, fs_error);
		if (fs_error)
		{
			SetError(L"could not publish the generated SDK directory", error, error_capacity);
			if (had_previous)
			{
				std::error_code restore_error;
				std::filesystem::rename(backup_sdk, context.sdk_directory, restore_error);
			}
			std::filesystem::remove(checksum_temp, fs_error);
			std::filesystem::remove_all(staging_root, fs_error);
			return PublishResult::Error;
		}

		if (!MoveFileExW(
				checksum_temp.c_str(),
				context.checksum_file.c_str(),
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		{
			SetSystemError(L"MoveFileExW(checksum)", GetLastError(), error, error_capacity);
			std::filesystem::remove_all(context.sdk_directory, fs_error);
			if (had_previous)
			{
				std::error_code restore_error;
				std::filesystem::rename(backup_sdk, context.sdk_directory, restore_error);
			}
			std::filesystem::remove(checksum_temp, fs_error);
			std::filesystem::remove_all(staging_root, fs_error);
			return PublishResult::Error;
		}

		if (had_previous)
			std::filesystem::remove_all(backup_sdk, fs_error);
		std::filesystem::remove_all(staging_root, fs_error);
		return PublishResult::Generated;
	}

	DWORD RunWorkerImpl(void* opaque)
	{
		const auto* worker = static_cast<const WorkerContext*>(opaque);
		if (worker == nullptr || worker->plugin_module == nullptr ||
			worker->stop_event == nullptr)
			return ERROR_INVALID_PARAMETER;

		std::filesystem::path executable;
		std::filesystem::path plugin;
		wchar_t error[512]{};
		if (!ModulePath(nullptr, executable, error, _countof(error)))
		{
			OutputDebugStringW(L"NTE Mods plugin SDK cache: ");
			OutputDebugStringW(error);
			OutputDebugStringW(L"\n");
			return ERROR_INVALID_DATA;
		}
		std::filesystem::path plugin_file;
		if (!ModulePath(
				worker->plugin_module,
				plugin_file,
				error,
				_countof(error)))
			return ERROR_INVALID_DATA;
		plugin = plugin_file.parent_path();

		CacheContext context{};
		const InspectResult inspection = InspectImpl(
			executable, plugin, context, error, _countof(error));
		if (inspection == InspectResult::Reusable)
		{
			OutputDebugStringW(L"NTE Mods plugin: reusing checksum-matched SDK cache.\n");
			return ERROR_SUCCESS;
		}
		if (inspection == InspectResult::Error)
		{
			OutputDebugStringW(L"NTE Mods plugin SDK cache inspection failed: ");
			OutputDebugStringW(error);
			OutputDebugStringW(L"\n");
			return ERROR_INVALID_DATA;
		}

		while (WaitForSingleObject(worker->stop_event, 0) == WAIT_TIMEOUT)
		{
			if (offsets::Initialize(worker->stop_event))
				break;
			if (WaitForSingleObject(worker->stop_event, OFFSET_RETRY_MS) != WAIT_TIMEOUT)
				return ERROR_CANCELLED;
		}
		const offsets::ResolvedOffsets* resolved = offsets::Get();
		if (resolved == nullptr)
			return ERROR_CANCELLED;

		const PublishResult published = RegenerateImpl(
			context,
			*resolved,
			&dumper7::GenerateCppSdk,
			worker->stop_event,
			error,
			_countof(error));
		if (published != PublishResult::Generated)
		{
			OutputDebugStringW(L"NTE Mods plugin SDK generation failed: ");
			OutputDebugStringW(error);
			OutputDebugStringW(L"\n");
			return ERROR_WRITE_FAULT;
		}
		OutputDebugStringW(L"NTE Mods plugin: generated and cached the current SDK.\n");
		return ERROR_SUCCESS;
	}

	InspectResult Inspect(
		const std::filesystem::path& executable_path,
		const std::filesystem::path& plugin_directory,
		CacheContext& context,
		wchar_t* error,
		size_t error_capacity) noexcept
	{
		try
		{
			return InspectImpl(
				executable_path,
				plugin_directory,
				context,
				error,
				error_capacity);
		}
		catch (const std::filesystem::filesystem_error&)
		{
			SetError(L"SDK cache inspection raised a filesystem exception", error, error_capacity);
		}
		catch (const std::exception&)
		{
			SetError(L"SDK cache inspection raised a C++ exception", error, error_capacity);
		}
		catch (...)
		{
			SetError(L"SDK cache inspection raised an unknown exception", error, error_capacity);
		}
		return InspectResult::Error;
	}

	PublishResult Regenerate(
		const CacheContext& context,
		const offsets::ResolvedOffsets& resolved,
		GenerateSdk generator,
		HANDLE stop_event,
		wchar_t* error,
		size_t error_capacity) noexcept
	{
		try
		{
			return RegenerateImpl(
				context,
				resolved,
				generator,
				stop_event,
				error,
				error_capacity);
		}
		catch (const std::filesystem::filesystem_error&)
		{
			SetError(L"SDK cache generation raised a filesystem exception", error, error_capacity);
		}
		catch (const std::exception&)
		{
			SetError(L"SDK cache generation raised a C++ exception", error, error_capacity);
		}
		catch (...)
		{
			SetError(L"SDK cache generation raised an unknown exception", error, error_capacity);
		}
		return PublishResult::Error;
	}

	DWORD WINAPI RunWorker(void* context)
	{
		try
		{
			return RunWorkerImpl(context);
		}
		catch (const std::exception&)
		{
			OutputDebugStringW(L"NTE Mods plugin SDK cache worker raised a C++ exception.\n");
		}
		catch (...)
		{
			OutputDebugStringW(L"NTE Mods plugin SDK cache worker raised an unknown exception.\n");
		}
		return ERROR_UNHANDLED_EXCEPTION;
	}
} // namespace nte::mods::sdk_cache
