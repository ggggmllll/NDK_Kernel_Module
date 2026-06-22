/*
 * loader.c — KPM loader 模块入口
 *
 * INIT_MODULE 自动跑 kallsyms_init / kmod_patch_init / compat_uaccess_init，
 * 之后 loader_init 依次串起各子系统，把完整的 KPM loader 搭起来：
 *   KPM 链表/锁 → CFI bypass → KP 兼容 API 表 → 自定义 syscall
 *
 * 各子系统的业务实现见同目录其它 .c；本文件只编排调用顺序。
 */
#include "kpm_internal.h"

static int loader_init(void)
{
    kpm_loader_init_subsys();   /* 链表 + 锁 */
    cfi_bypass_init();          /* hook __cfi_slowpath / report_cfi_failure */
    kp_compat_init();           /* loader_api 表 + local_syms */
    kpm_syscall_register();     /* 注册 KPM loader 自定义 syscall */
    klog("kpm_loader: initialized\n");
    return 0;
}

static void loader_exit(void)
{
    kpm_syscall_unregister();
    unload_all_kpms();
    cfi_bypass_exit();
    klog("kpm_loader: exited\n");
}

INIT_MODULE(loader_init)
EXIT_MODULE(loader_exit)
