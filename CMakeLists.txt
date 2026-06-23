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

# ---- 内核模块编译标志 ----
# 内核模块由【真机内核】的模块加载器（arch/arm64/kernel/module.c）加载，
# 它不支持 GOT 重定位（R_AARCH64_ADR_GOT_PAGE=311 / LD64_GOT_LO12_NC=312）。
# NDK 默认 -fPIC 会让外部符号引用走 GOT → insmod 报
#   "module loader: unsupported RELA relocation: 311"。
# 必须用内核 code model 编译：-fno-PIC -mcmodel=small（对齐参考实现
# loader/template/Makefile 的 CFLAGS_BASE）。
#
# 另外 NDK 工具链文件默认注入用户态 Bionic 设施，在内核态会崩：
#   -fstack-protector*：canary 走 MRS TPIDR_EL0 + [tls+0x28]（Bionic
#     TLS_SLOT_STACK_GUARD）。内核态 TPIDR_EL0 是用户 TLS 指针 → 读用户地址
#     → PAN 触发 "kernel access to user memory"。必须 -fno-stack-protector。
#   _FORTIFY_SOURCE：依赖 Bionic 的 __*_chk，内核没有。关掉。
# 注意：只加在内核侧 OBJECT 库上，fixup_ko 是 Android PIE 用户态程序，保持默认。
set(KMOD_FLAGS
    -fno-PIC -mcmodel=small -fvisibility=hidden
    -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0)

# ---- kmod 基础设施库（模板自带；含 CFI entry stubs）----
add_library(kmod OBJECT
    src/kmod_kernel.c
    src/kmod_uaccess.c
    src/kmod_hook.c
    src/cfi_entry_stubs.S)
target_include_directories(kmod PUBLIC include)
target_compile_options(kmod PRIVATE ${KMOD_FLAGS})

# ---- fixup_ko（上机修补工具，Android 可执行）----
add_subdirectory(fixup_ko)

# ---- 使用者模块 ----
add_subdirectory(${MODULE_DIR})
