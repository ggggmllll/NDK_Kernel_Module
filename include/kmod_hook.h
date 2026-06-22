#ifndef KMOD_HOOK_H
#define KMOD_HOOK_H

#include "kmod_types.h"

/*
 * kmod_hook.h — ARM64 inline hook（声明）
 *
 * 实现在 src/kmod_hook.c。依赖 kmod_kernel 的 patch 基础设施
 *（kmod_patch_init() 之后可用）。
 *
 *   do_hook(func, replace, backup)
 *       把 func 入口 patch 成跳到 replace；*backup 返回重定位后的原指令
 *       序列地址，调用它等于调用原函数。
 *   do_unhook(func)
 *       还原 func 入口。
 */

long do_hook(void *func, void *replace, void **backup);
void do_unhook(void *func);

/* 判断地址是否落在 hook thunk 页内（cfi_bypass 用）*/
int is_thunk_area(unsigned long addr);

/* ---- wrap hook（before/after 回调，基于 thunk 池）----
 *   hook_wrap(func, argno, before, after, udata)
 *       每次 func 被调用时：before(fargs,udata) → 原函数 → after(fargs,udata)。
 *       fargs 布局见 dispatch_main 注释（KernelPatch 兼容）。argno 目前未用。
 *   unhook(func) 还原。*/
long hook_wrap(void *func, int argno, void *before, void *after, void *udata);
void unhook(void *func);

/* ---- syscall hook ----
 *   fp_wrap_syscalln：改 sys_call_table[nr] 指向 thunk（函数指针 hook）。
 *   inline_wrap_syscalln：inline hook syscall handler 函数入口。
 *   is_compat：兼容（32 位）syscall 表，目前未区分。*/
long fp_wrap_syscalln(int nr, int narg, int is_compat,
                      void *before, void *after, void *udata);
void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after);
long inline_wrap_syscalln(int nr, int narg, int is_compat,
                          void *before, void *after, void *udata);
void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after);

/* ---- 自定义 syscall 注册 ----
 * 占用一个 sys_call_table slot 作为模块和 userspace 的私有通信通道
 *（syscall 派发是 blr x16，无 /proc 那种 kCFI 类型 hash 检查）。
 *
 * 使用者 handler 按 section 约定写（module.lds 已配对）：
 *   __attribute__((used, section(".kcfi_prefix.syscall_handler")))
 *   static const u64 syscall_handler_prefix = 0;        // 8 字节占位
 *   __attribute__((section(".text.syscall_handler")))
 *   static long syscall_handler(unsigned long a0, unsigned long a1,
 *                               unsigned long a2, unsigned long a3) { ... }
 */

enum {
    KMOD_SYSCALL_SLOT_EMPTY = 0,   /* orig == 0，slot 未用 */
    KMOD_SYSCALL_SLOT_GARBAGE,     /* orig 页对齐等非法值，多半超出 NR_syscalls */
    KMOD_SYSCALL_SLOT_USED,        /* orig 是合法 handler（在用）*/
    KMOD_SYSCALL_SLOT_UNKNOWN = -1 /* sys_call_table 未解析 / nr 非法 */
};

/* 查询 slot 状态。使用者据此决定是否 register_syscall。*/
int syscall_slot_status(int nr);

/* 注册：patch sys_call_table[nr] → handler；若 orig 在用且 6.x wrapper 内核，
 * 偷原 hash 写进 prefix（8 字节占位，lds 紧贴 handler）。
 * 返回原 orig（unregister 用）；负值表示 sys_call_table 未解析。*/
long register_syscall(int nr, void *handler, u64 *prefix);

/* 恢复 sys_call_table[nr] = orig。*/
void unregister_syscall(int nr, unsigned long orig);

/* ---- 便捷宏：声明 handler + 注册 ----
 * 把 prefix 占位 + section 属性 + 固定签名都包进去，使用者只写函数体。
 * section 名固定为 syscall_handler（和 module.lds 的配对一致）。
 *
 *   KMOD_SYSCALL_HANDLER(my_syscall)
 *   {
 *       if (klog) klog("called: %lu\n", a0);
 *       return 0;
 *   }
 *   // init 里：
 *   long orig = KMOD_REGISTER_SYSCALL(448, my_syscall);
 *   // exit 里：
 *   unregister_syscall(448, orig);
 */
#define KMOD_SYSCALL_HANDLER(name)                                        \
    __attribute__((used, section(".kcfi_prefix.syscall_handler")))         \
    static const u64 name##_prefix = 0;                                   \
    __attribute__((section(".text.syscall_handler"),                       \
                   no_sanitize("cfi"), no_sanitize("kcfi")))               \
    static long name(unsigned long a0, unsigned long a1,                   \
                     unsigned long a2, unsigned long a3)

#define KMOD_REGISTER_SYSCALL(nr, name) \
    register_syscall((nr), name, (u64 *)&(name##_prefix))

#endif /* KMOD_HOOK_H */
