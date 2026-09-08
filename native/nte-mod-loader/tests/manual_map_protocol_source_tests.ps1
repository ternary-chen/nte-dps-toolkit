$ErrorActionPreference = "Stop"

$loaderRoot = Split-Path -Parent $PSScriptRoot
$nativeRoot = Split-Path -Parent $loaderRoot
$protocol = Get-Content -LiteralPath (
    Join-Path $nativeRoot "nte-mods-plugin/include/nte_mods_plugin_manual_map.hpp") -Raw
$manualMapLoader = Get-Content -LiteralPath (
    Join-Path $loaderRoot "shim/src/ManualMapLoader.cpp") -Raw
$pluginEntry = Get-Content -LiteralPath (
    Join-Path $nativeRoot "nte-mods-plugin/src/nte_mods_plugin.cpp") -Raw

if ($protocol -notmatch 'ATTACH_SENTINEL[\s\S]+IMAGE_SIGNATURE[\s\S]+SelectReservedParameter') {
    throw "The shared manual-map attach protocol is incomplete."
}
if ($manualMapLoader -notmatch 'SelectReservedParameter\([\s\S]+dllBytes\.data\(\)[\s\S]+remoteParams[\s\S]+ManualMapDll\([\s\S]+reservedParameter') {
    throw "The manual mapper does not select the shared marker for the signed plugin image."
}
$dllMain = [regex]::Match(
    $pluginEntry,
    'BOOL\s+WINAPI\s+DllMain\([\s\S]+?\n\}',
    [System.Text.RegularExpressions.RegexOptions]::Singleline).Value
if ($dllMain -notmatch 'if\s*\(reason\s*==\s*DLL_PROCESS_ATTACH\)[\s\S]+RecordPluginModule\(module\);') {
    throw "The plugin does not record its module during process attach."
}
if ($dllMain -notmatch 'if\s*\(nte::mods::manual_map::IsExplicitAttach\(reserved\)\)\s*nte::mods::InitializeRecordedPluginRuntime\(\);\s*else\s*nte::mods::ScheduleRecordedPluginRuntimeInitialization\(\);') {
    throw "The plugin does not gate direct manual-map startup on the explicit marker and schedule proxy startup."
}

Write-Output "manual_map_protocol_source_tests: PASS"
