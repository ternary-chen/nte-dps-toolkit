// 能力探测 PE fixture，仅导出协议数据，测试不加载 DLL。
#include "nte/loader/Injection/ShimProtocol.h"
extern "C" __declspec(dllexport) const char NteLoaderShimProtocol[] =
#ifdef LEGACY_SHIM_PROTOCOL
    "NTE_LOADER_SHIM_ABI_V2;init=1056;manualmap=1;loadlibrary=1";
#else
    NTE_LOADER_SHIM_PROTOCOL_SIGNATURE;
#endif
