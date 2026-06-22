# NDK_Kernel_Module —— 用 Android NDK 构建可加载内核模块的工程模板
#
# 流水线（CMake）：
#   使用者模块.c + cfi_entry_stubs.S + kmod 基础设施 → ld -r -T module.lds
#   → <MODULE_NAME>_merged.o → KPatcher → <MODULE_NAME>.ko
#   （上机后由 fixup_ko 完成 vermagic/CRC/this_module/build-id 等修补）
#
# 工具链：Android NDK（CMakePresets.json 的 android-arm64 preset）。
# 依赖 host 工具 KPatcher：https://github.com/ggggmllll/KPatcher
#
cmake_minimum_required(VERSION 3.18)

project(ndk_kernel_module LANGUAGES C CXX ASM)

# ---- 模块配置（使用者可覆盖）----
set(MODULE_DIR  "loader" CACHE STRING "使用者模块子目录")
set(MODULE_NAME "loader" CACHE STRING "模块名（决定 .ko 文件名 / .modinfo name）")

# ---- KPatcher（host 工具，独立仓库）----
# 查找顺序：1) -DKPATCHER=...；2) 仓库 bin/kpatcher；3) PATH
# 使用者：把 kpatcher 放进 bin/，或装到 PATH，或 -DKPATCHER=/path/to/kpatcher
find_program(KPATCHER
    NAMES kpatcher KPatcher
    HINTS "${CMAKE_SOURCE_DIR}/bin"
    DOC "Path to KPatcher (https://github.com/ggggmllll/KPatcher)")
if(NOT KPATCHER)
    message(FATAL_ERROR
        "kpatcher not found. 把它放进本仓库的 bin/，或装到 PATH，"
        "或传 -DKPATCHER=/path/to/kpatcher。\n"
        "KPatcher 源码：https://github.com/ggggmllll/KPatcher")
endif()
message(STATUS "KPatcher: ${KPATCHER}")

# ---- kmod 基础设施库（模板自带；含 CFI entry stubs）----
add_library(kmod OBJECT
    src/kmod_kernel.c
    src/kmod_uaccess.c
    src/kmod_hook.c
    src/cfi_entry_stubs.S)
target_include_directories(kmod PUBLIC include)

# ---- fixup_ko（上机修补工具，Android 可执行）----
add_subdirectory(fixup_ko)

# ---- 使用者模块 ----
add_subdirectory(${MODULE_DIR})
