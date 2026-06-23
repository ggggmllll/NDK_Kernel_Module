/*
 * kp_compat.c — 给 KPM 解析的符号表（local_syms）
 *
 * local_syms 把 loader / kmod 模板**已经实现**的函数（hook_wrap/unhook/
 * fp_wrap_syscalln/compat_copy_to_user/字符串/kallsyms_lookup 等）和
 * loader 自己的 data（kver/kpver/has_syscall_wrapper/printk ptr/
 * sp_el0_* 等）注册成一张符号表。KPM 的 undefined symbol 解析时，
 * kpm_kallsyms_lookup 先查这张表，再查内核 —— 命中 local_syms 的就不会
 * 去内核找（这些符号内核本来也没有）。
 *
 * KPM 调 loader 能力就走这套符号解析（不再经 struct kpm_api / reserved）。
 *
 * 字符串函数是 kmod_string.h 的 static inline，这里取 & 取到的是本 .c
 * 的副本地址，功能等价。
 *
 * 移植自 examples/loader_full.c Section 5（local_syms/init）。
 */
#include "kpm_internal.h"

#define KP_VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

/* =========================================================================
 * loader data（local_syms 引用；放 .data 让地址文件持久，便于 KPM 用
 * MOV+MOVK 嵌入地址）。
 * ========================================================================= */
static u32 kver   __attribute__((used, section(".data"))) = 0;
static u32 kpver  __attribute__((used, section(".data"))) = KP_VERSION(0, 13, 0);

static int kp_has_syscall_wrapper        __attribute__((used, section(".data"))) = 0;
static void (*kp_printk_ptr)(const char *fmt, ...)
    __attribute__((used, section(".data")));

/* KernelPatch asm/current.h 兼容值（Android GKI 5.10）。KPM 的 get_current()
 * 逻辑依赖这些常量，按符号名解析到这里的值。 */
static int kp_sp_el0_is_current          __attribute__((used, section(".data"))) = 1;
static int kp_thread_info_in_task        __attribute__((used, section(".data"))) = 1;
static int kp_sp_el0_is_thread_info      __attribute__((used, section(".data"))) = 0;
static int kp_thread_size                __attribute__((used, section(".data"))) = 16384;
static int kp_task_in_thread_info_offset __attribute__((used, section(".data"))) = 0;

/* hook_unwrap_remove — KP 链式 unhook 的兼容包装；简化版直接 unhook。 */
void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    (void)before; (void)after;
    if (remove && func) unhook(func);
}

/* =========================================================================
 * local_syms 符号表
 *
 * is_func: 1=函数符号（-fPIC KPM 经 GOT 双重解引用，需 wrap 成变量地址）；
 *          0=data（直接用地址）。kpm_build_got 用 is_local_data_sym 区分。
 * ========================================================================= */
static struct {
    const char *name;
    unsigned long addr;
    int is_func;
} local_syms[] = {
    {"kpver",                    0, 0},
    {"kver",                     0, 0},
    {"compat_copy_to_user",      0, 1},
    {"strlen",                   0, 1},
    {"strncat",                  0, 1},
    {"strncpy",                  0, 1},
    {"strcpy",                   0, 1},
    {"memcpy",                   0, 1},
    {"memmove",                  0, 1},
    {"memset",                   0, 1},
    {"memcmp",                   0, 1},
    {"strcmp",                   0, 1},
    {"hook_wrap",                0, 1},
    {"unhook",                   0, 1},
    {"fp_wrap_syscalln",         0, 1},
    {"fp_unwrap_syscalln",       0, 1},
    {"inline_wrap_syscalln",     0, 1},
    {"inline_unwrap_syscalln",   0, 1},
    {"compat_strncpy_from_user", 0, 1},
    {"kallsyms_lookup_name",     0, 1},
    {"has_syscall_wrapper",      0, 0},
    {"printk",                   0, 0},
    {"hook_unwrap_remove",       0, 1},
    {"sp_el0_is_current",          0, 0},
    {"thread_info_in_task",        0, 0},
    {"sp_el0_is_thread_info",      0, 0},
    {"thread_size",                0, 0},
    {"task_in_thread_info_offset", 0, 0},
    /* libc 基础（kmod_string.h 的 static inline 副本地址）*/
    {"strncmp", 0, 1},
    {"strchr",  0, 1},
    {"strrchr", 0, 1},
    {"strstr",  0, 1},
    {"strcat",  0, 1},
    {"strnlen", 0, 1},
    {"memchr",  0, 1},
    {"memrchr", 0, 1},
    {"strtol",  0, 1},
    {"strtoul", 0, 1},
    {"snprintf", 0, 1},
    {"compat_copy_from_user", 0, 1},
    {"hook", 0, 1},
    {NULL, 0, 0}
};

static unsigned long local_sym_lookup(const char *name)
{
    for (int i = 0; local_syms[i].name; i++)
        if (strcmp(name, local_syms[i].name) == 0)
            return local_syms[i].addr;
    return 0;
}

int is_local_data_sym(unsigned long addr)
{
    for (int i = 0; local_syms[i].name; i++)
        if (!local_syms[i].is_func && local_syms[i].addr == addr)
            return 1;
    return 0;
}

/* KPM 符号解析：先查 local_syms（loader 提供的），再查内核。
 * kpm_elf.c 的 kpm_simplify_symbols 用这个；local_syms[19] 也指它。*/
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
unsigned long kpm_kallsyms_lookup(const char *name)
{
    unsigned long local;
    if (!name) return 0;
    local = local_sym_lookup(name);
    if (local) return local;
    return kallsyms_lookup(name);
}

/* =========================================================================
 * 填 local_syms 地址 + 探测内核版本
 * ========================================================================= */
static void local_syms_init(void)
{
    local_syms[0].addr  = (unsigned long)&kpver;
    local_syms[1].addr  = (unsigned long)&kver;
    local_syms[2].addr  = (unsigned long)&compat_copy_to_user;
    local_syms[3].addr  = (unsigned long)&strlen;
    local_syms[4].addr  = (unsigned long)&strncat;
    local_syms[5].addr  = (unsigned long)&strncpy;
    local_syms[6].addr  = (unsigned long)&strcpy;
    local_syms[7].addr  = (unsigned long)&memcpy;
    local_syms[8].addr  = (unsigned long)&memmove;
    local_syms[9].addr  = (unsigned long)&memset;
    local_syms[10].addr = (unsigned long)&memcmp;
    local_syms[11].addr = (unsigned long)&strcmp;
    local_syms[12].addr = (unsigned long)&hook_wrap;
    local_syms[13].addr = (unsigned long)&unhook;
    local_syms[14].addr = (unsigned long)&fp_wrap_syscalln;
    local_syms[15].addr = (unsigned long)&fp_unwrap_syscalln;
    local_syms[16].addr = (unsigned long)&inline_wrap_syscalln;
    local_syms[17].addr = (unsigned long)&inline_unwrap_syscalln;
    local_syms[18].addr = (unsigned long)&compat_strncpy_from_user;
    local_syms[19].addr = (unsigned long)&kpm_kallsyms_lookup;
    local_syms[20].addr = (unsigned long)&kp_has_syscall_wrapper;
    kp_printk_ptr = (typeof(kp_printk_ptr))klog;
    local_syms[21].addr = (unsigned long)&kp_printk_ptr;
    local_syms[22].addr = (unsigned long)&hook_unwrap_remove;
    local_syms[23].addr = (unsigned long)&kp_sp_el0_is_current;
    local_syms[24].addr = (unsigned long)&kp_thread_info_in_task;
    local_syms[25].addr = (unsigned long)&kp_sp_el0_is_thread_info;
    local_syms[26].addr = (unsigned long)&kp_thread_size;
    local_syms[27].addr = (unsigned long)&kp_task_in_thread_info_offset;
    /* libc 基础函数 */
    local_syms[28].addr = (unsigned long)&strncmp;
    local_syms[29].addr = (unsigned long)&strchr;
    local_syms[30].addr = (unsigned long)&strrchr;
    local_syms[31].addr = (unsigned long)&strstr;
    local_syms[32].addr = (unsigned long)&strcat;
    local_syms[33].addr = (unsigned long)&strnlen;
    local_syms[34].addr = (unsigned long)&memchr;
    local_syms[35].addr = (unsigned long)&memrchr;
    local_syms[36].addr = (unsigned long)&strtol;
    local_syms[37].addr = (unsigned long)&strtoul;
    local_syms[38].addr = (unsigned long)&snprintf;
    local_syms[39].addr = (unsigned long)&compat_copy_from_user;
    local_syms[40].addr = (unsigned long)&do_hook;   /* KernelPatch hook() 别名 */

    /* 探测内核版本：linux_banner（最稳）→ init_uts_ns.name.release（偏移试探）*/
    int major = 0, minor = 0, patch = 0;
    const char *release = 0;

    unsigned long banner_addr = kallsyms_lookup("linux_banner");
    if (banner_addr) {
        const char *b = (const char *)banner_addr;
        const char *prefix = "Linux version ";
        const char *p = b;
        while (*prefix && *p == *prefix) { p++; prefix++; }
        if (!*prefix) release = p;
    }
    if (!release) {
        unsigned long uts_addr = kallsyms_lookup("init_uts_ns");
        if (uts_addr) {
            int offsets[] = { 130, 134, 4 + 130, 8 + 130, 0 };
            for (int i = 0; offsets[i] >= 0; i++) {
                const char *cand = (const char *)(uts_addr + offsets[i]);
                if (*cand >= '0' && *cand <= '9') { release = cand; break; }
            }
        }
    }
    if (release) {
        const char *p = release;
        while (*p >= '0' && *p <= '9') { major = major * 10 + (*p - '0'); p++; }
        if (*p == '.') p++;
        while (*p >= '0' && *p <= '9') { minor = minor * 10 + (*p - '0'); p++; }
        if (*p == '.') p++;
        while (*p >= '0' && *p <= '9') { patch = patch * 10 + (*p - '0'); p++; }
        if (major > 0) {
            kver = KP_VERSION(major, minor, patch);
            klog("kpm_loader: kernel %d.%d.%d (kver=%08x)\n", major, minor, patch, kver);
        }
    }
    if (major == 0) {
        kver = KP_VERSION(5, 10, 0);
        klog("kpm_loader: cannot detect kernel version, default kver=%08x\n", kver);
    }
    klog("kpm_loader: kpver=%08x\n", kpver);
}

void kp_compat_init(void)
{
    local_syms_init();

    /* has_syscall_wrapper：__arm64_sys_openat 存在 → wrapper 内核（GKI 5.10+）*/
    if (kallsyms_lookup("__arm64_sys_openat"))
        kp_has_syscall_wrapper = 1;
    klog("kpm_loader: has_syscall_wrapper=%d\n", kp_has_syscall_wrapper);

    klog("kpm_loader: kp_compat ready (local_syms)\n");
}
