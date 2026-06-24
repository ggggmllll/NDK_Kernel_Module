#ifndef KPM_INTERNAL_H
#define KPM_INTERNAL_H

/*
 * kpm_internal.h — KPM loader 各 .c 共享的内部声明（不对外）
 *
 * 公共基础设施走 include/ 下的头（kmod_module.h 等）；本头只放 KPM loader
 * 自身的数据结构与子系统 init/exit 约定。
 *
 * 注：KPM 调 loader 能力走 local_syms 符号解析（hook_wrap/kpm_kallsyms_lookup/
 * compat_copy_to_user 等），不再经 reserved 参数传 API 表 —— struct kpm_api
 * 已移除。KPM init 的 reserved 参数保留（签名兼容 KernelPatch KPM）但传 NULL。
 */

#include "kmod_module.h"
#include "kmod_hook.h"

/* =========================================================================
 * KPM 模块入口 / 控制函数类型
 * ========================================================================= */
typedef long (*kpm_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_ctl0call_t)(const char *ctl_args, char *out_msg, int outlen);
typedef long (*kpm_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*kpm_exitcall_t)(void *reserved);

/* =========================================================================
 * 加载到内存的 KPM 模块
 * ========================================================================= */
struct kpm_module {
    struct {
        const char *base, *name, *version, *license, *author, *description;
    } info;
    char *args, *ctl_args;
    kpm_initcall_t *init;
    kpm_ctl0call_t *ctl0;
    kpm_ctl1call_t *ctl1;
    kpm_exitcall_t *exit;
    unsigned int size;
    void *start;
    unsigned int text_size;   /* PAGE_ALIGN'd executable region */
    unsigned int text_used;   /* actual text bytes (pre-align) */
    void *got_base;           /* GOT slot array (vmalloc'd, freed on unload) */
    struct list_head list;
};

/* =========================================================================
 * 全局状态（定义在对应 .c）
 * ========================================================================= */
extern struct list_head kpm_modules; /* kpm_elf.c */
extern struct mutex kpm_lock;        /* kpm_elf.c */

/* KPM loader 自定义 syscall 号（TODO: 按真机可用 slot 选；骨架暂用 448）*/
#define KPM_SYSCALL_NR 448

/* =========================================================================
 * KPM 内存区域跟踪（cfi_bypass.c 实现）
 * ========================================================================= */
void kpm_area_add(unsigned long start, unsigned long size);
void kpm_area_remove(unsigned long start);
int  is_kpm_area(unsigned long addr);

/* =========================================================================
 * local_syms 查询（kp_compat.c 实现）
 * ========================================================================= */
int is_local_data_sym(unsigned long addr);

/* KPM 符号解析：先查 local_syms（loader 提供的），再查内核。kpm_elf.c 的
 * kpm_simplify_symbols 用这个（让 kpver/kver/hook_wrap/compat_copy_to_user
 * 等 loader 符号能被 KPM 解析）。 */
unsigned long kpm_kallsyms_lookup(const char *name);

/* =========================================================================
 * 各子系统 init/exit（loader_init 按声明顺序调用）
 * ========================================================================= */

/* kpm_elf.c：KPM 链表/锁 + ET_REL 解析/重定位/加载 */
void kpm_loader_init_subsys(void);
long load_kpm_file(const char *path, const char *args);
long unload_kpm_name(const char *name);
long unload_all_kpms(void);

/* CTL 命令（kpm_elf.c）：按名查模块调 ctl0，供 kpm_syscall CTL 用 */
long api_kpm_control(const char *name, const char *args, char *out_msg, int outlen);

/* cfi_bypass.c：hook __cfi_slowpath / report_cfi_failure，让无 CFI 的 KPM 通过 */
void cfi_bypass_init(void);
void cfi_bypass_exit(void);

/* seccomp_bypass.c：按 UID 豁免 seccomp，让目标进程能调自定义 syscall 加载 KPM */
void seccomp_bypass_init(void);
void seccomp_bypass_exit(void);

/* kp_compat.c：KernelPatch KPM 兼容符号表（local_syms）*/
void kp_compat_init(void);

/* kpm_syscall.c：自定义 syscall（load/unload/kaddr 等命令通道）*/
void kpm_syscall_register(void);
void kpm_syscall_unregister(void);

#endif /* KPM_INTERNAL_H */
