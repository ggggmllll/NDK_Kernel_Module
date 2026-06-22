#ifndef KMOD_MODULE_H
#define KMOD_MODULE_H

#include "kmod_kernel.h"
#include "kmod_uaccess.h"

/*
 * kmod_module.h — 模块入口封装（INIT_MODULE / EXIT_MODULE 宏）
 *
 * cfi_entry_stubs.S 提供 init_module / cleanup_module 符号（带 kCFI hash 的
 * 跳转表），它们 tail-call 到 init_module_impl / cleanup_module_impl —— 也就
 * 是这两个宏生成的函数。
 *
 * 宏内部先把基础设施跑起来（kallsyms → patch → uaccess），再调用使用者的
 * func。使用者只需写自己的 init/exit 业务函数：
 *
 *   static int  my_init(void) { klog("hi\n"); return 0; }
 *   static void my_exit(void) { klog("bye\n"); }
 *   INIT_MODULE(my_init)
 *   EXIT_MODULE(my_exit)
 *
 * 不需要 uaccess 的模块，可以在 INIT_MODULE 之后自己再调一次
 * compact_uaccess_init()（幂等），或改写宏去掉那一行。
 */

#define INIT_MODULE(func)                              \
    int init_module_impl(void) {                       \
        kallsyms_init();                               \
        kmod_patch_init();                             \
        compact_uaccess_init();                        \
        return func();                                 \
    }

#define EXIT_MODULE(func)                              \
    void cleanup_module_impl(void) {                   \
        func();                                        \
    }

#endif /* KMOD_MODULE_H */
