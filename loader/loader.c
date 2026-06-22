/*
 * loader.c —— 用 kmod 框架实现的示例内核模块。
 *
 * INIT_MODULE 宏内部依次跑 kallsyms_init / kmod_patch_init /
 * compact_uaccess_init（把 klog / patch / uaccess 都准备好），再调 loader_init。
 * 要 hook 内核函数、注册自定义 syscall，在 loader_init 里调
 * do_hook(...) / KMOD_REGISTER_SYSCALL(...) 即可。
 */

#include "kmod_module.h"

static int loader_init(void)
{
    klog("loader: module loaded\n");
    return 0;
}

static void loader_exit(void)
{
    klog("loader: module unloaded\n");
}

INIT_MODULE(loader_init)
EXIT_MODULE(loader_exit)
