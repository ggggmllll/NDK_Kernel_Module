/*
 * kpm_syscall.c — KPM loader 自定义 syscall（userspace 命令通道）
 *
 * 移植自 examples/loader_full.c Section 10。占用 sys_call_table[KPM_SYSCALL_NR]
 * 作私有通信口 —— syscall 派发是 blr x16，无 /proc 那种 kCFI 类型 hash 检查。
 *
 * userspace: syscall(KPM_SYSCALL_NR, cmd, arg1, arg2, arg3)
 *   LOAD(0)   a1=path, a2=args   → 加载 KPM
 *   UNLOAD(1) a1=name (""=all)   → 卸载
 *   LIST(2)                       → 列出已加载模块（返回数量，详情进 klog）
 *   KADDR(3) a1=hex_addr         → 设 kallsyms 地址（stub）
 *   CTL(4)                       → KPM ctl0 调用（stub，依赖 ④ api_kpm_control）
 *   BYPASS(5)                    → 重新 hook CFI（幂等）
 *
 * wrapper 内核（5.x+ ARM64）a0 是 pt_regs*；非 wrapper a0=cmd。kpm_extract_cmd
 * 用 a0 是否落在内核地址空间自动区分（pt_regs* 是内核地址，cmd 是小整数）。
 *
 * register/unregister 用模板的 KMOD_REGISTER_SYSCALL / unregister_syscall
 *（内部处理 sys_call_table 解析 + slot 写 + 6.x kCFI hash 偷取）。
 */
#include "kpm_internal.h"

#define KPM_CMD_LOAD    0
#define KPM_CMD_UNLOAD  1
#define KPM_CMD_LIST    2
#define KPM_CMD_KADDR   3
#define KPM_CMD_CTL     4
#define KPM_CMD_BYPASS  5

static unsigned long kpm_orig_syscall = 0;

/* 从 syscall 帧取命令和参数。
 * wrapper 内核 a0 = pt_regs*（内核地址）；非 wrapper a0 = cmd（小整数）。
 * 用 a0 是否 >= KERNEL_SPACE_BASE 自动区分。 */
static int kpm_extract_cmd(unsigned long a0, unsigned long a1,
                            unsigned long a2, unsigned long a3,
                            unsigned long *arg1, unsigned long *arg2,
                            unsigned long *arg3)
{
    if (a0 >= KERNEL_SPACE_BASE) {
        unsigned long *regs = (unsigned long *)a0;
        *arg1 = regs[1];
        *arg2 = regs[2];
        *arg3 = regs[3];
        return (int)regs[0];
    }
    *arg1 = a1;
    *arg2 = a2;
    *arg3 = a3;
    return (int)a0;
}

KMOD_SYSCALL_HANDLER(kpm_syscall)
{
    unsigned long arg1, arg2, arg3;
    int cmd = kpm_extract_cmd(a0, a1, a2, a3, &arg1, &arg2, &arg3);

    switch (cmd) {

    case KPM_CMD_LOAD: {
        char path[256];
        char args[256];
        if (compat_strncpy_from_user(path, (const char __user *)arg1,
                                      sizeof(path)) < 0)
            return -14;   /* EFAULT */
        if (arg2) {
            if (compat_strncpy_from_user(args, (const char __user *)arg2,
                                          sizeof(args)) < 0)
                return -14;
        } else {
            args[0] = 0;
        }
        return load_kpm_file(path, args[0] ? args : NULL);
    }

    case KPM_CMD_UNLOAD: {
        char name[128];
        if (compat_strncpy_from_user(name, (const char __user *)arg1,
                                      sizeof(name)) < 0)
            return -14;
        if (name[0] == 0) {
            unload_all_kpms();
            return 0;
        }
        return unload_kpm_name(name);
    }

    case KPM_CMD_LIST: {
        int count = 0;
        struct kpm_module *mod;
        mutex_lock(&kpm_lock);
        list_for_each_entry(mod, &kpm_modules, list) {
            klog("kpm_loader: [%d] %s ver=%s\n",
                 count, mod->info.name, mod->info.version);
            count++;
        }
        mutex_unlock(&kpm_lock);
        if (count == 0)
            klog("kpm_loader: (no modules loaded)\n");
        return count;
    }

    case KPM_CMD_KADDR:
        /* TODO: 设 kallsyms_lookup_name_fn + 重新触发 patch/uaccess 解析。
         * 需 kmod_kernel 暴露 setter；骨架先记日志。 */
        klog("kpm_loader: KADDR stub (arg1=%lx) — re-resolve 待实现\n", arg1);
        return 0;

    case KPM_CMD_CTL: {
        char name[128];
        char args[256];
        char out[512];
        long rc;
        if (compat_strncpy_from_user(name, (const char __user *)arg1,
                                      sizeof(name)) < 0)
            return -14;
        if (compat_strncpy_from_user(args, (const char __user *)arg2,
                                      sizeof(args)) < 0)
            return -14;
        rc = api_kpm_control(name, args, out, sizeof(out));
        klog("kpm_loader: ctl %s %s -> %ld: %s\n", name, args, rc, out);
        return rc;
    }

    case KPM_CMD_BYPASS:
        cfi_bypass_init();   /* 幂等：重新 hook CFI 符号 */
        return 0;

    default:
        return -22;   /* EINVAL */
    }
}

void kpm_syscall_register(void)
{
    kpm_orig_syscall = KMOD_REGISTER_SYSCALL(KPM_SYSCALL_NR, kpm_syscall);
    klog("kpm_loader: syscall %d registered (orig=%lx)\n",
         KPM_SYSCALL_NR, kpm_orig_syscall);
}

void kpm_syscall_unregister(void)
{
    unregister_syscall(KPM_SYSCALL_NR, kpm_orig_syscall);
}
