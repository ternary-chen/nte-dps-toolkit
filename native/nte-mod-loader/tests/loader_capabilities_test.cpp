// 只读验证内嵌 shim 协议；fixture DLL 从不被执行。
#include "nte/loader/App/LoaderCapabilities.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

std::vector<char> Read(const wchar_t* path) {
    std::ifstream stream(std::filesystem::path(path), std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
int failures=0;
#define CHECK(x) do { if (!(x)) { ++failures; std::cerr << "FAIL " #x << '\n'; } } while (0)
int wmain(int argc,wchar_t** argv) {
    if(argc!=3) return 2;
    CHECK(std::strstr(nte::loader::LoaderCapabilitiesJson(true), "nte_capture_runtime_v1") != nullptr);
    CHECK(std::strstr(nte::loader::LoaderCapabilitiesJson(false), "nte_capture_runtime_v1") == nullptr);
    const auto valid=Read(argv[1]);
    auto old=Read(argv[2]);
    CHECK(nte::loader::EmbeddedShimProtocolMatches(valid.data(),valid.size()));
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(old.data(),old.size()));
    old.insert(old.end(),std::begin(nte::loader::kShimProtocolSignature),std::end(nte::loader::kShimProtocolSignature));
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(old.data(),old.size())); // raw text is insufficient
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(nullptr,0));
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(valid.data(),sizeof(IMAGE_DOS_HEADER)));
    auto altered=valid;
    const auto at=std::search(altered.begin(),altered.end(),
        std::begin(nte::loader::kShimProtocolSignature),std::end(nte::loader::kShimProtocolSignature));
    CHECK(at!=altered.end());
    if(at!=altered.end()) *at='X';
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(altered.data(),altered.size()));
    altered=valid;
    auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(altered.data());
    auto* nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(altered.data()+dos->e_lfanew);
    nt->FileHeader.Machine=IMAGE_FILE_MACHINE_I386;
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(altered.data(),altered.size()));
    nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress=0xfffffff0;
    CHECK(!nte::loader::EmbeddedShimProtocolMatches(altered.data(),altered.size()));
    std::cout<<(failures?"LOADER_CAPABILITIES_FAILED":"LOADER_CAPABILITIES_PASSED")<<'\n';
    return failures?1:0;
}
