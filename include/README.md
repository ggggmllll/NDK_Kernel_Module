# include/ + src/ — 内核模块开发基础设施

NDK 编译内核模块时没有 `<linux/*>`、也没有 libc。本目录提供模块开发所需的最小
自包含基础设施 —— **include/ 放声明，src/ 放实现**，src/ 作为库编译一次、
多 `.c` 模块链接共享。

## 结构

| 文件 | 内容 |
|------|------|
| `include/kmod_types.h` | 基本类型（`u8`/`u16`/.../`bool`）、宏（`offsetof`/`container_of`/`ARRAY_SIZE`）、常量（`PAGE_SIZE`/`ALIGN`/`GFP_KERNEL`）、双链表 `list_head` |
| `include/kmod_string.h` | 最小 libc：`strcmp`/`strlen`/`memcpy`/`memset` 等（`static inline`，无状态，多 .c 包含无副作用） |
| `include/kmod_kernel.h` | 声明：`klog` / `kallsyms_init` / `resolve_printk` / `kallsyms_lookup` / `__cfi_slowpath` + 类型（`mutex`/`kprobe`/`file`）+ kernel API `extern` |
| `include/kmod_uaccess.h` | 声明：`compact_uaccess_init` / `compact_copy_to_user` / `compact_copy_from_user` / `compact_strncpy_from_user` |
| `src/kmod_kernel.c` | `klog`（extern 全局）+ kallsyms 实现；`kallsyms_lookup_name_fn` / `kallsyms_patch` 文件 static |
| `src/kmod_uaccess.c` | uaccess wrap 实现；cached kernel fn / STTRB·LDTRB asm / ttbr0 包裹均文件 static |

依赖链：`kmod_uaccess.h` → `kmod_types.h`，`kmod_kernel.h` → `kmod_string.h` → `kmod_types.h`。
模块源码一般 `#include <kmod_kernel.h>`（带出 string/types）；用 uaccess 再加 `<kmod_uaccess.h>`。

## 使用（CMake 集成的概念）

```cmake
# kmod 基础设施库（编一次，所有模块共享）
add_library(kmod STATIC src/kmod_kernel.c src/kmod_uaccess.c)
target_include_directories(kmod PUBLIC include)

# 使用者的模块
add_library(mymodule OBJECT mymodule.c)
target_link_libraries(mymodule PRIVATE kmod)
```

> 顶层 `CMakeLists.txt` 的具体集成待定，这里只是概念。

## 模块 init 顺序

基础设施要在模块 init 早期按顺序调一次：

```c
kallsyms_init();          /* 三策略解析 kallsyms_lookup_name
                           * (fixup_ko 标记 / kprobe / sprintf 扫描)
                           * 内部已调 resolve_printk()，之后 klog 可用 */
compact_uaccess_init();   /* 解析内核 copy_to/from_user + strncpy_from_user
                           * + ttbr0_enable/disable */
/* 用户业务 init ... */
```

之后即可用：`klog("...")`、`kallsyms_lookup("printk")`、`compact_copy_from_user(...)` 等。

> 计划提供一个 `INIT_MODULE(func)` 宏把上面这套顺序 + 用户 init 包起来，
> 让模块只写自己的 `func`。

## 设计要点

- **`klog` 是 extern 全局**（像 stdio 的 `stdout`）：模块直接 `klog("...")`。
  `kallsyms_init()` 内部 `resolve_printk` 解析（5.x `printk` / 6.x `_printk`）。
  不直接引用 printk 符号 —— 避免 5.10 上的 GOT 重定位（type 311）。

- **`kallsyms_patch` 不暴露**：fixup_ko 按字符串扫描 `.ko` 找魔术标记
  (`KPM_KALLSYMS_NAME_PATCH_SLOT_V1X`)，不依赖符号导出，所以它在
  `kmod_kernel.c` 里是文件 static。

- **`resolve_printk` 已暴露**：`kallsyms_init` 内部调过；模块想在某次 klog
  失效后重试解析也可单独调（幂等：`if (klog) return`）。

- **uaccess 两层策略**：优先调内核自己的 `copy_to_user` / `copy_from_user` /
  `strncpy_from_user`（`compact_uaccess_init` 解析，最稳）；内核 fn 不可用时
  退到 STTRB / LDTRB inline（ARMv8.0 unprivileged + `__ex_table`）。LDTRB 在
  部分 5.10（如 MTK 真机）fault handler 行为不一致（qemu 正常、真机崩），
  所以**只作 fallback**，不首选。STTRB/LDTRB fallback 前后包
  `__uaccess_ttbr0_enable/disable`（5.x SW PAN；6.x 硬件 PAN 符号不存在则跳过）。

- **多 `.c` 友好**：实现都在 `src/*.c`（库编译一次），文件 static 变量单实例，
  多 `.c` 模块链接共享 —— 没有"头文件 static 全局多副本"问题，也不需要每个
  模块自己 `extern` 声明 + 定义。
