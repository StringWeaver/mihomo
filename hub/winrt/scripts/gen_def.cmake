# gen_def.cmake -- Generate .def file from dumpbin /exports output
# Uses a simpler approach: invoke a PowerShell one-liner

file(READ "${BUILD_DIR}/golib_exports.txt" exports_content)

# Write a PowerShell script to extract symbols
file(WRITE "${BUILD_DIR}/gen_def.ps1" "
$lines = Get-Content '${BUILD_DIR}/golib_exports.txt'
$symbols = $lines | Where-Object { $_ -match '^\\s+\\d+\\s+[0-9A-Fa-f]+\\s+[0-9A-Fa-f]+\\s+([A-Za-z0-9_]+)' } | ForEach-Object { $matches[1] }
$content = \"LIBRARY golib`nEXPORTS`n\"
foreach (\$s in \$symbols) { \$content += \"    \$s`n\" }
Set-Content -Path '${BUILD_DIR}/golib.def' -Value \$content -Encoding ASCII
Write-Host \"Generated golib.def with \$(\$symbols.Count) exports\"
")

execute_process(
    COMMAND powershell -ExecutionPolicy Bypass -File "${BUILD_DIR}/gen_def.ps1"
    RESULT_VARIABLE ps_result
)
message(STATUS "gen_def.ps1 result: ${ps_result}")
