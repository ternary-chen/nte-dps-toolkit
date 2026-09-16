// 仅供标准 Loader 定向测试，无初始化线程或游戏行为。
#if defined(CAPTURE_FIXTURE)
extern "C" __declspec(dllexport) const char NteCaptureRuntimeSignature[] =
#ifdef OLD_CAPTURE_SIGNATURE
    "NTE_CAPTURE_RUNTIME_V0";
#else
    "NTE_CAPTURE_RUNTIME_V1";
#endif
extern "C" __declspec(dllexport) int FixtureProbe() { return 42; }
#elif defined(HOST_FIXTURE)
extern "C" __declspec(dllimport) int FixtureDependency();
extern "C" __declspec(dllexport) const char NteCombatDebugProxySignature[] =
    "NTE_COMBAT_DEBUG_D3D12_PROXY_V2";
extern "C" __declspec(dllexport) int FixtureProbe() { return FixtureDependency(); }
#else
extern "C" __declspec(dllexport) int FixtureProbe() { return 0; }
#endif
