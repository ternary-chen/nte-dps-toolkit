# nte-mod-loader

常驻式游戏 Mod 注入加载器。监控游戏启动器进程，通过 **manual map 注入**（Simple-Manual-Map-Injector 语义）把 shim 注入启动器，再由 shim 的 `CreateProcessW` hook 在游戏进程（HTGame.exe）创建时注入用户指定的 payload DLL，并确认注入成功。

## 组成

| 目录 | 内容 |
|------|------|
| `app/`   | 控制台入口（`nte-mod-loader.exe`），内嵌 shim 为资源 101 |
| `core/`  | 核心静态库：进程监控、启动器定位、配置、注入、日志 |
| `shim/`  | `nte_shim.dll`：注入到启动器的 CreateProcessW hook 载荷 |
| `tests/` | 单元/集成测试（`nte-mod-loader-tests.exe`） |
| `third_party/` | vendored 依赖：MinHook (BSD-2-Clause)、Simple-Manual-Map-Injector (MIT) |

## 构建

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  '.\native\nte-mod-loader\nte-mod-loader.sln' `
  /m /t:Rebuild /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
```

产物输出到 `bin\Release\`（`nte-mod-loader.exe`、`nte_shim.dll`、`nte-mod-loader-tests.exe`）。

Release 的 Loader 与内嵌 shim 不生成链接调试信息，避免嵌入本机 PDB 路径；Debug 保留调试信息。对外交付包不得携带调试符号。

## 使用

发布包中 Loader 由 NTE 控制台直接管理，不需要放进游戏目录。目录结构固定为：

```text
NTE-DPS-TOOL/
├── nte-dps-tool.exe
├── nte-mod-loader.exe
└── plugins/
    └── dwmapi.dll
```

`nte-mod-loader` 是代理加载无效时使用的备用方式。在「Mod 工坊」中把加载方式切换
到 **Mod Loader（备用）** 后打开开关即可启动；该开关不会把 `dwmapi.dll` 复制到
`HTGame.exe` 旁边。开发者单独运行 Loader 时也应保持上述
相对目录，或显式传入 `--dll <path>`。

```powershell
# 常驻监控: 启动器打开 → 注入 shim → 游戏创建 → 注入 payload DLL
.\nte-mod-loader.exe
```

Release 可执行文件内嵌 `requireAdministrator` manifest，双击或从终端启动时会由 Windows 显示 UAC 提权。

- `--dll <path>`：指定注入到 HTGame.exe 的 payload DLL（默认 `<exe 目录>\plugins\dwmapi.dll`，也可用环境变量 `NTE_MOD_LOADER_DLL` 覆盖）
- `--payload-load-mode manualmap|loadlibrary`：默认 `manualmap` 保持旧语义；`loadlibrary` 在游戏进程用绝对路径调用 `LoadLibraryExW`，正常登记模块，并用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS` 解析依赖。非法值或缺值拒绝启动。
- `--dry-run`：预览模式，不做任何进程/文件变更
- `--once`：完成一轮探测即退出
- `--monitor-timeout <seconds>`：监控超时；`0` 表示持续监控
- `--stop-event <name>` / `--owner-pid <pid>`：控制台管理会话使用的内部生命周期参数
- 环境变量：`NTE_MOD_LOADER_LAUNCHER`（启动器路径覆盖）、`NTE_MOD_LOADER_SPAWN_LAUNCHER=1`（spawn 官方启动器）、`NTE_MOD_LOADER_MONITOR_TIMEOUT`（监控超时秒数，默认 120；`0` 表示持续监控）

### 机器可读能力查询

调用 `nte-mod-loader.exe --capabilities-json --dry-run --once`。新版本在任何监控、提取临时文件或注入之前输出一行 JSON 并退出；`--dry-run --once` 让忽略新参数的旧版本也只做预览。调用方必须取得正常退出的完整 JSON，检查 `schema_version=1`、`component="nte-mod-loader"`、`embedded_shim_compatible=true`，且 `payload_load_modes` 包含 `loadlibrary`。本期采集运行时还必须检查 `shim_protocol_version=3` 和 `payload_kinds` 包含 `nte_capture_runtime_v1`；只具有通用标准加载能力不足以确认该种类支持。不能从进程存在或普通文本输出推断能力。原 EXE 的 requireAdministrator manifest 仍适用，查询不会绕过 Windows 提升要求。

成功（exit 0）：`{"schema_version":1,"component":"nte-mod-loader","shim_protocol_version":3,"embedded_shim_compatible":true,"payload_load_modes":["manualmap","loadlibrary"],"payload_kinds":["nte_capture_runtime_v1"],"managed_session":true}`。

EXE 只读自身资源 101 的有界 x64 PE 导出，要求 `NteLoaderShimProtocol` 数据与协议 3、1056 字节初始化参数、两种 payload 模式及 `nte_capture_runtime_v1` 种类声明一致：`NTE_LOADER_SHIM_ABI_V3;init=1056;manualmap=1;loadlibrary=1;nte_capture_runtime_v1=1`。旧协议 2 的内嵌 shim 不支持该种类声明。缺资源、旧 shim 或不匹配声明返回 exit 3、`embedded_shim_compatible=false`、空 `payload_load_modes`、空 `payload_kinds` 与 `error_code="embedded_shim_protocol_mismatch"`。不执行内嵌 DLL，不以旁边的 shim 文件代替内嵌资源。构建仍由现有 ProjectReference/CopyRebuiltShim 在资源编译前嵌入重建的 shim。

该声明是能力协议，不是安全签名或固定二进制 SHA 白名单；可信来源的同名替换仍可使用。能力通过不代表宿主、管道或游戏业务已通过实机验收。

## 工作方式

1. 启动后静默，仅输出 `[INFO] NTE Mod Loader started`
2. 常驻监控 `NTEGlobalLauncher.exe` / `NTELauncher.exe` / `NTEGame.exe` / `NTEGlobalGame.exe`
3. 检测到受信安装根内的启动器 → 输出进程名和 PID → manual map 注入 shim；临时文件在本轮监控结束后删除
4. shim hook `kernel32!CreateProcessW`；HTGame.exe 创建时按所选模式加载 payload（默认 manual map），确认后写带会话 nonce 的 `%TEMP%\nte_loaded_<pid>_<nonce>` 标记
5. loader 只接受当前会话标记，确认后输出 payload 文件名和游戏 PID
6. 监控期间启动器/游戏重开会自动重新注入；控制台停止事件、控制台进程退出、Ctrl+C 或监控超时会先终止本次会话已注入 shim 的启动器，再结束 loader

### 本期最小采集运行时加载

本期采集交付目标为无界面的 `NTE_Capture.dll`，不依赖 `NTE-Platform.dll`；UETools 工具界面、MCP 和插件宿主不进入 Calc 的公开采集组件包。D3D 入口使用最小代理标准加载同一采集运行时；可选 Loader 直接加载 `NTE_Capture.dll`，无需经过工具宿主或插件初始化。

先按上节能力查询确认 EXE 与内嵌 shim 支持标准加载，再使用：

```powershell
.\nte-mod-loader.exe --capabilities-json --dry-run --once
.\nte-mod-loader.exe --dll "<采集组件目录>\NTE_Capture.dll" --payload-load-mode loadlibrary
```

shim 仍以原有 manual map 方式进入受信启动器。标准 payload 分支只排队有界工作线程，保持调用方原有的挂起/恢复语义；等待游戏系统模块就绪后，以绝对路径调用 `LoadLibraryExW` 并确认实际模块路径匹配请求。`NTE_Capture.dll` 使用标准加载并额外验证实际导出数据 `NteCaptureRuntimeSignature=NTE_CAPTURE_RUNTIME_V1`（包含 NUL）；缺失或旧签名不能写成功标记，并释放本次取得的加载引用。该种类不要求 `NTE-Platform.dll`、GUI 或按 `~` 激活；采集初始化由运行时自身负责。代码中仅对文件名为 `d3d12.dll` 的 payload 保留专用宿主签名和平台目录检查，该检查不适用于本期直接加载的采集运行时。

本会话 loaded 标记只确认 DLL 加载，不代表采集管道、握手或业务快照已就绪。远程调用使用 x64 参数块，完整保留 64 位模块句柄；线程退出码不充当模块句柄。等待超时时不释放仍可能被远程线程访问的代码和参数，不重试该调用；这些分配在目标进程结束时回收。Loader 停止仍沿用原会话清理，不等同于卸载游戏内采集运行时。

此模式需要配套重建 Loader 和内嵌 shim，不能混用旧资源 101。上述调用与源码及定向 fixture 验证不代表新版 EXE、采集 DLL 已完成构建或实机验收；历史同名产物不能因此视为当前组件。

## 测试

```powershell
.\bin\Release\nte-mod-loader-tests.exe
```

预期输出 `ALL_TESTS_PASSED`。
