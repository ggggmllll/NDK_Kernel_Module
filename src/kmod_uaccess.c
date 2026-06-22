/*
 * kmod_uaccess.c — kmod_uaccess.h 的实现（跨内核/用户态安全拷贝）
 *
 * 库文件：CMake 编译一次，多 .c 模块链接共享。cached 的内核 fn 地址在
 * compat_uaccess_init()（模块 init 早期）一次解析。
 */

#include "kmod_uaccess.h"
#include "kmod_kernel.h"

/* ==================== cached kernel fn（文件 static） ==================== */
static unsigned long cached_copy_to_user = 0;
static unsigned long cached_copy_from_user = 0;
static unsigned long cached_strncpy_from_user = 0;
static unsigned long cached_ttbr0_enable = 0;
static unsigned long cached_ttbr0_disable = 0;

/* ==================== STTRB / LDTRB inline fallback（文件 static） ====================
 * ARMv8.0 unprivileged 访问 + 自带 __ex_table（旧式 8 字节，兼容 5.10）。
 * fault 时 rem 保留为剩余未拷贝字节数。 */

__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long compat_sttr_copy_to(void *to, const void *from, unsigned long n)
{
    unsigned long to_a  = (unsigned long)to;
    unsigned long frm_a = (unsigned long)from;
    unsigned long rem   = n;

    __asm__ volatile(
        "1:  cbz %2, 2f\n"
        "    ldrb w9, [%1], #1\n"
        "kmod_sttr_insn_site:\n"
        "    sttrb w9, [%0]\n"
        "    add %0, %0, #1\n"
        "    sub %2, %2, #1\n"
        "    b 1b\n"
        "2:\n"
        "kmod_sttr_fixup:\n"
        ".pushsection __ex_table, \"a\"\n"
        "    .align 2\n"
        "    .long (kmod_sttr_insn_site - .)\n"
        "    .long (kmod_sttr_fixup - .)\n"
        ".popsection\n"
        : "+r" (to_a), "+r" (frm_a), "+r" (rem)
        :
        : "memory", "x9"
    );
    return rem;
}

__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long compat_ldtr_copy_from(void *to, const void *from, unsigned long n)
{
    unsigned long to_a  = (unsigned long)to;
    unsigned long frm_a = (unsigned long)from;
    unsigned long rem   = n;

    __asm__ volatile(
        "1:  cbz %2, 2f\n"
        "kmod_ldtr_insn_site:\n"
        "    ldtrb w9, [%1]\n"
        "    strb w9, [%0], #1\n"
        "    add %1, %1, #1\n"
        "    sub %2, %2, #1\n"
        "    b 1b\n"
        "2:\n"
        "kmod_ldtr_fixup:\n"
        ".pushsection __ex_table, \"a\"\n"
        "    .align 2\n"
        "    .long (kmod_ldtr_insn_site - .)\n"
        "    .long (kmod_ldtr_fixup - .)\n"
        ".popsection\n"
        : "+r" (to_a), "+r" (frm_a), "+r" (rem)
        :
        : "memory", "x9"
    );
    return rem;
}

__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static long compat_ldtrstr_from_user(char *dest, const char __user *src, long max)
{
    long copied = 0;
    unsigned long s = (unsigned long)src;
    char *d = dest;
    long rem = max - 1;

    __asm__ volatile(
        "1:  cbz %w3, 3f\n"
        "kmod_ldtrstr_insn_site:\n"
        "    ldtrb w9, [%1]\n"
        "    strb w9, [%0], #1\n"
        "    add %1, %1, #1\n"
        "    sub %w3, %w3, #1\n"
        "    add %w2, %w2, #1\n"
        "    cbz w9, 2f\n"
        "    b 1b\n"
        "2:\n"
        "    mov %w3, #0\n"
        "    b 4f\n"
        "3:\n"
        "    mov %w3, #0\n"
        "4:\n"
        "kmod_ldtrstr_fixup:\n"
        ".pushsection __ex_table, \"a\"\n"
        "    .align 2\n"
        "    .long (kmod_ldtrstr_insn_site - .)\n"
        "    .long (kmod_ldtrstr_fixup - .)\n"
        ".popsection\n"
        : "+r" (d), "+r" (s), "+r" (copied), "+r" (rem)
        :
        : "memory", "x9"
    );

    *d = 0;
    return rem ? -1 : copied;
}

/* ==================== SW PAN 包裹（文件 static） ==================== */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void uaccess_ttbr0_begin(void)
{
    if (cached_ttbr0_enable) ((void (*)(void))cached_ttbr0_enable)();
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void uaccess_ttbr0_end(void)
{
    if (cached_ttbr0_disable) ((void (*)(void))cached_ttbr0_disable)();
}

/* ==================== init（暴露） ====================
 * 解析内核 uaccess 函数 + ttbr0 开关。不同内核版本符号名不同，逐个尝试。
 * 必须在 kallsyms_init() 之后调用。 */
void compat_uaccess_init(void)
{
    static const char *ctou[] = {
        "_copy_to_user", "copy_to_user", "__arch_copy_to_user",
        "raw_copy_to_user", "__copy_to_user", NULL
    };
    static const char *cfou[] = {
        "_copy_from_user", "copy_from_user", "__arch_copy_from_user",
        "raw_copy_from_user", "__copy_from_user", NULL
    };
    for (int i = 0; ctou[i]; i++) {
        unsigned long a = kallsyms_lookup(ctou[i]);
        if (a) { cached_copy_to_user = a; break; }
    }
    for (int i = 0; cfou[i]; i++) {
        unsigned long a = kallsyms_lookup(cfou[i]);
        if (a) { cached_copy_from_user = a; break; }
    }
    cached_strncpy_from_user = kallsyms_lookup("strncpy_from_user");
    cached_ttbr0_enable = kallsyms_lookup("__uaccess_ttbr0_enable");
    cached_ttbr0_disable = kallsyms_lookup("__uaccess_ttbr0_disable");
}

/* ==================== wrap（暴露） ==================== */

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
unsigned long compat_copy_to_user(void *to, const void *from, unsigned long n)
{
    if ((unsigned long)to >= KERNEL_SPACE_BASE) {
        __builtin_memcpy(to, from, n);
        return 0;
    }
    if (cached_copy_to_user) {
        typedef unsigned long (*fn_t)(void *, const void *, unsigned long);
        return ((fn_t)cached_copy_to_user)(to, from, n);
    }
    unsigned long rem;
    uaccess_ttbr0_begin();
    rem = compat_sttr_copy_to(to, from, n);
    uaccess_ttbr0_end();
    return rem;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
unsigned long compat_copy_from_user(void *to, const void *from, unsigned long n)
{
    unsigned long rem;

    if ((unsigned long)from >= KERNEL_SPACE_BASE) {
        __builtin_memcpy(to, from, n);
        return 0;
    }
    if (cached_copy_from_user) {
        typedef unsigned long (*fn_t)(void *, const void *, unsigned long);
        rem = ((fn_t)cached_copy_from_user)(to, from, n);
    } else {
        uaccess_ttbr0_begin();
        rem = compat_ldtr_copy_from(to, from, n);
        uaccess_ttbr0_end();
    }
    if (rem) memset((char *)to + (n - rem), 0, rem);
    return rem;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
long compat_strncpy_from_user(char *dest, const char __user *src, long max)
{
    long ret;

    if (max <= 0) return 0;

    if ((unsigned long)src >= KERNEL_SPACE_BASE) {
        strncpy(dest, (const char *)src, (unsigned long)max);
        dest[max - 1] = 0;
        return (long)strlen(dest);
    }
    if (cached_strncpy_from_user) {
        typedef long (*fn_t)(char *, const char *, long);
        return ((fn_t)cached_strncpy_from_user)(dest, src, max);
    }

    uaccess_ttbr0_begin();
    ret = compat_ldtrstr_from_user(dest, src, max);
    uaccess_ttbr0_end();
    return ret;
}
