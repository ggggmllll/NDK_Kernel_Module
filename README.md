# NDK_Kernel_Module

用 [Android NDK](https://developer.android.com/ndk) 构建可加载 Linux 内核模块（`.ko`）的工程模板。不需要内核源码树，自带一套内核态 C 基础设施（kmod 库）+ `.o → .ko` 转换流水线 + 上机修补工具。

## 工作原理

正常编译内核模块要内核源码树 + Kbuild。本模板绕过它：用 NDK 的 clang 把模块源码编成可重定位 `.o`，再用 host 工具 [KPatcher](https://github.com/ggggmllll/KPatcher) 把 `.o` 修补成内核认可的 `.ko`（补 `.modinfo` / `__versions` / `.gnu.linkonce.this_module` 等），上机后由 `fixup_ko` 用真机的 vermagic / CRC / `struct module` 布局完成最终修补。

```
模块源码 + kmod 库 + cfi_entry_stubs.S
   ↓ NDK clang -c
*.o
   ↓ ld -r -T module.lds
loader_merged.o
   ↓ KPatcher（host）
loader.ko（模板）
   ↓ fixup_ko（Android 真机）
可 insmod 的 .ko
```

## 依赖

- **Android NDK**（测试用 r29；路径写在 `CMakePresets.json`，按本机改）
- **[KPatcher](https://github.com/ggggmllll/KPatcher)**（host 工具，独立仓库，GPLv2）
- CMake ≥ 3.18 + Ninja

## Quickstart

```bash
git clone https://github.com/ggggmllll/NDK_Kernel_Module
cd NDK_Kernel_Module

# 1. 单独 build KPatcher，得到 kpatcher 可执行（见 KPatcher 仓库 README）
# 2. 放进本模板的 bin/（或装到 PATH，或 -DKPATCHER=/path/to/kpatcher）
cp /path/to/kpatcher bin/kpatcher

# 3. 构建（NDK 交叉编译 → ld -r → KPatcher）
cmake --preset android-arm64
cmake --build out/build/android-arm64
# → out/build/android-arm64/loader.ko
```

`bin/` 在 `.gitignore` 里，不会被提交。

## 目录结构

```
NDK_Kernel_Module/
├── CMakeLists.txt           顶层（kmod 库 + fixup_ko + add_subdirectory(MODULE_DIR)）
├── CMakePresets.json        android-arm64 preset（NDK 工具链）
├── module.lds               linker script（CFI 跳转表 + syscall handler 的 kCFI prefix 配对）
├── include/                 kmod 基础设施头文件（声明）
├── src/                     kmod 库实现 + cfi_entry_stubs.S
├── loader/                  默认模块子目录（示例 loader.c）
├── fixup_ko/                上机修补工具（Android 可执行）
└── examples/                loader_full.c（提取源，参考用，不参与构建）
```

## kmod 基础设施

NDK 编译内核模块时没有 `<linux/*>`、也没有 libc。`include/` + `src/` 提供最小自包含基础设施（库编译一次，多 .c 模块共享）：

| 头文件 | 内容 |
|---|---|
| `kmod_types.h` | 基本类型（u8/u16/.../bool）、宏（offsetof/container_of）、双链表 list_head |
| `kmod_string.h` | 最小 libc：strcmp/strlen/memcpy/memset 等（static inline，无状态）|
| `kmod_kernel.h` | klog / klog_deferred / kallsyms 基础设施 / kernel API extern / patch 基础设施（call_*、pgtable、patch_insn）/ kmod_read_file |
| `kmod_uaccess.h` | 跨内核/用户态安全拷贝（compact_copy_to/from_user、compact_strncpy_from_user）|
| `kmod_hook.h` | ARM64 inline hook（do_hook/hook_wrap）+ syscall hook + 自定义 syscall 注册 |
| `kmod_module.h` | INIT_MODULE / EXIT_MODULE 宏（模块入口封装）|

实现细节见 [include/README.md](include/README.md)。

## 写自己的模块

默认模块在 `loader/`（`MODULE_DIR` 变量可改）。写一个 `.c` 放进去：

```c
#include "kmod_module.h"
#include "kmod_hook.h"

static int my_init(void)
{
    klog("mymod: loaded\n");
    /* hook 内核函数：  do_hook(func, replace, &backup); */
    /* 注册自定义 syscall：KMOD_REGISTER_SYSCALL(448, my_syscall); */
    return 0;
}

static void my_exit(void)
{
    klog("mymod: unloaded\n");
}

INIT_MODULE(my_init)   /* 展开成 init_module_impl（内部先跑 kallsyms/patch/uaccess init）*/
EXIT_MODULE(my_exit)   /* 展开成 cleanup_module_impl */
```

`init_module` / `cleanup_module` 符号由 `cfi_entry_stubs.S` 提供（带 kCFI hash 的跳转表），它们 tail-call 到 `*_impl`。

自定义 syscall 用宏（自动生成 kCFI prefix 占位 + section 属性）：

```c
KMOD_SYSCALL_HANDLER(my_syscall)
{
    klog("syscall called, a0=%lu\n", a0);
    return 0;
}
/* init 里：*/ long orig = KMOD_REGISTER_SYSCALL(448, my_syscall);
/* exit 里：*/ unregister_syscall(448, orig);
```

换模块子目录：`cmake -DMODULE_DIR=mymodule -DMODULE_NAME=mymodule`。

## 上机

```bash
adb push out/build/android-arm64/loader.ko      /data/local/tmp/
adb push out/build/android-arm64/fixup_ko/fixup_ko /data/local/tmp/

# 设备上（root）：用真机参考 .ko 修补 vermagic / CRC / this_module
/data/local/tmp/fixup_ko /data/local/tmp/loader.ko        # 自动搜参考 .ko
# 或指定参考：fixup_ko <reference.ko> <loader.ko>

insmod /data/local/tmp/loader.ko
dmesg | tail        # "loader: module loaded"
rmmod loader
```

## 工具链

`CMakePresets.json` 的 `android-arm64` preset 指向 NDK 的 `android.toolchain.cmake`（路径按本机硬编码，开源移植时改成 `${env:ANDROID_NDK_HOME}`）。VS 内置 CMake 和命令行 `cmake --preset` 都能识别。

## 协议

本项目基于 **GNU General Public License v2** 开源，详见 [LICENSE](LICENSE)。

依赖 [KPatcher](https://github.com/ggggmllll/KPatcher)（GPLv2，host 工具）；`fixup_ko` 上机工具与 KPatcher 配合使用。
