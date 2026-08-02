cmake_minimum_required(VERSION 3.20)
project(VpnProxyApp CXX)

# ============================================================
# Configuration
# ============================================================
set(SDK_VER "10.0.26100.0" CACHE STRING "Windows SDK version")
set(GO_BUILD_TAGS "with_gvisor" CACHE STRING "Go build tags")
set(APPX_NAME "VpnProxyApp" CACHE STRING "APPX package name")

# MIHOMO_DIR defaults to the parent of this CMakeLists.txt
if(NOT MIHOMO_DIR)
    set(MIHOMO_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
endif()

# Find Go
find_program(GO_EXEC go REQUIRED)

# Find MSVC and Windows SDK paths
set(SDK_BASE "C:/Program Files (x86)/Windows Kits/10")
set(SDK_INCLUDE "${SDK_BASE}/Include/${SDK_VER}")
set(SDK_LIB "${SDK_BASE}/Lib/${SDK_VER}")
set(SDK_BIN "${SDK_BASE}/bin/${SDK_VER}")

# ============================================================
# Build output directories
# ============================================================
set(BUILD_DIR ${CMAKE_BINARY_DIR})
set(APPX_STAGING ${BUILD_DIR}/appx_staging)

# Source directories
set(WINRT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(CPP_DIR ${WINRT_DIR}/cpp)
set(APPX_DIR ${WINRT_DIR}/appx)
set(SCRIPTS_DIR ${WINRT_DIR}/scripts)

# ============================================================
# Step 1: Build Go c-shared DLL (golib.dll)
# ============================================================
add_custom_command(
    OUTPUT ${BUILD_DIR}/golib.dll ${BUILD_DIR}/golib.h
    COMMAND ${GO_EXEC} build -buildmode=c-shared -tags ${GO_BUILD_TAGS}
            -o ${BUILD_DIR}/golib.dll .
    WORKING_DIRECTORY ${WINRT_DIR}
    COMMENT "Building Go c-shared DLL (mihomo + winrt exports)"
)
add_custom_target(golib_dll ALL DEPENDS ${BUILD_DIR}/golib.dll)

# ============================================================
# Step 2: Generate MSVC import library from Go DLL
# ============================================================
find_program(DUMPBIN_EXEC dumpbin
    HINTS "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64"
    REQUIRED)
find_program(LIB_EXEC lib
    HINTS "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64"
    REQUIRED)

add_custom_command(
    OUTPUT ${BUILD_DIR}/golib.lib
    COMMAND ${DUMPBIN_EXEC} /exports golib.dll > golib_exports.txt
    COMMAND ${CMAKE_COMMAND}
            -DBUILD_DIR=${BUILD_DIR}
            -P ${SCRIPTS_DIR}/gen_def.cmake
    COMMAND ${LIB_EXEC} /def:golib.def /out:golib.lib /machine:x64
    DEPENDS ${BUILD_DIR}/golib.dll
    WORKING_DIRECTORY ${BUILD_DIR}
    COMMENT "Generating MSVC import library (golib.lib)"
)
add_custom_target(golib_lib ALL DEPENDS ${BUILD_DIR}/golib.lib)

# ============================================================
# Step 3: Build C++/WinRT VPN Plugin DLL
# ============================================================
add_library(VpnPlugin SHARED
    ${CPP_DIR}/vpnplugin.cpp
    ${CPP_DIR}/dll_export.cpp
)
target_compile_features(VpnPlugin PRIVATE cxx_std_20)
target_compile_options(VpnPlugin PRIVATE /EHsc /W4 /O2)

target_include_directories(VpnPlugin PRIVATE
    ${BUILD_DIR}                                          # golib.h
    "${SDK_INCLUDE}/cppwinrt"                             # C++/WinRT projection headers
    "${SDK_INCLUDE}/winrt"                                # WinRT ABI headers
    "${SDK_INCLUDE}/um"
    "${SDK_INCLUDE}/shared"
    "${SDK_INCLUDE}/ucrt"
    ${CPP_DIR}                                            # vpnplugin.h
)

target_link_directories(VpnPlugin PRIVATE
    ${BUILD_DIR}            # golib.lib
    "${SDK_LIB}/um/x64"
    "${SDK_LIB}/ucrt/x64"
)

target_link_libraries(VpnPlugin PRIVATE
    golib.lib
    WindowsApp.lib
    ole32.lib
    oleaut32.lib
)

add_dependencies(VpnPlugin golib_lib)

set_target_properties(VpnPlugin PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${APPX_STAGING}
)

# ============================================================
# Step 4: Stage APPX contents
# ============================================================
add_custom_command(
    OUTPUT ${APPX_STAGING}/AppxManifest.xml
    COMMAND ${CMAKE_COMMAND} -E make_directory ${APPX_STAGING}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${APPX_STAGING}/assets
    COMMAND ${CMAKE_COMMAND} -E copy ${APPX_DIR}/AppxManifest.xml ${APPX_STAGING}/
    COMMAND ${CMAKE_COMMAND} -E copy ${BUILD_DIR}/golib.dll ${APPX_STAGING}/
    DEPENDS VpnPlugin golib_lib ${APPX_DIR}/AppxManifest.xml
    COMMENT "Staging APPX contents"
)

# ============================================================
# Step 5: Package and sign APPX
# ============================================================
set(APPX_OUTPUT ${BUILD_DIR}/${APPX_NAME}.msix)

add_custom_command(
    OUTPUT ${APPX_OUTPUT}
    COMMAND "${SDK_BIN}/x64/makeappx.exe" pack
            /d ${APPX_STAGING} /p ${APPX_OUTPUT} /nv
    COMMAND "${SDK_BIN}/x64/signtool.exe" sign
            /fd SHA256 /a
            /f ${WINRT_DIR}/certs/dev.pfx
            /p $ENV{SIGN_PASSWORD}
            ${APPX_OUTPUT}
    DEPENDS ${APPX_STAGING}/AppxManifest.xml VpnPlugin
    COMMENT "Building and signing APPX/MSIX package"
)

add_custom_target(appx ALL DEPENDS ${APPX_OUTPUT})
