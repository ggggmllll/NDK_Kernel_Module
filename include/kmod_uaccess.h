#ifndef KMOD_UACCESS_H
#define KMOD_UACCESS_H

#include "kmod_types.h"

/*
 * kmod_uaccess.h — 跨内核态/用户态的安全拷贝（声明）
 *
 * 实现在 src/kmod_uaccess.c（库编译一次，多 .c 模块共享）。
 * kmod_string.h 的 memcpy/memmove 不能跨内核/用户态（PAN fault）。
 *
 * 策略：优先调内核自己的 copy_to_user / copy_from_user / strncpy_from_user
 *（compact_uaccess_init 解析）；内核 fn 不可用时退到 STTRB/LDTRB inline，
 * 前后包 __uaccess_ttbr0_enable/disable（5.x SW PAN）。
 *
 * 模块 init 早期（kallsyms_init 之后）调一次 compact_uaccess_init()。
 */

void compact_uaccess_init(void);

/* 内核 → 用户。返回未拷贝字节数（0 = 成功）。 */
unsigned long compact_copy_to_user(void *to, const void *from, unsigned long n);

/* 用户 → 内核。返回未拷贝字节数（0 = 成功）；fault 时把目标缓冲尾部清零。 */
unsigned long compact_copy_from_user(void *to, const void *from, unsigned long n);

/* 用户 → 内核字符串。返回 >=0 = 长度（不含 NUL），-1 = fault。
 * dest 最多读 max-1 字节，保证 NUL 结尾。 */
long compact_strncpy_from_user(char *dest, const char __user *src, long max);

#endif /* KMOD_UACCESS_H */
