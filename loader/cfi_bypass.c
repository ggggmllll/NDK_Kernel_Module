/*
 * cfi_bypass.c — KPM 内存区域跟踪 + CFI bypass
 *
 * 两块职责：
 *   1. kpm_areas[]：跟踪已加载 KPM 的内存区域。kpm_elf.c 的
 *      kpm_alloc/kpm_free_exec 调 add/remove；is_kpm_area 给 cfi bypass 用。
 *   2. hook 内核 __cfi_slowpath / report_cfi_failure：KPM 用普通 clang 编
 *      （无 CFI 类型 hash），loader 通过函数指针调 KPM 会撞 CFI。对落在
 *      KPM 区域或 hook thunk 区域的目标（should_cfi_pass）跳过检查，其它
 *      仍交给内核原函数。
 *
 * 移植自 examples/loader_full.c Section 5b。
 */
#include "kpm_internal.h"

/* =========================================================================
 * CFI 相关类型
 * ========================================================================= */
struct pt_regs;
typedef void (*cfi_slowpath_fn)(u64 id, void *ptr, void *diag);
enum bug_trap_type {
    BUG_TRAP_TYPE_NONE = 0,
    BUG_TRAP_TYPE_WARN = 1,
    BUG_TRAP_TYPE_BUG  = 2,
};

/* =========================================================================
 * KPM 内存区域跟踪
 * ========================================================================= */
#define KPM_AREA_MAX 16
static struct {
    unsigned long start;
    unsigned long end;
} kpm_areas[KPM_AREA_MAX];
static int kpm_area_count = 0;

void kpm_area_add(unsigned long start, unsigned long size)
{
    if (kpm_area_count < KPM_AREA_MAX) {
        kpm_areas[kpm_area_count].start = start;
        kpm_areas[kpm_area_count].end   = start + size;
        kpm_area_count++;
    }
}

void kpm_area_remove(unsigned long start)
{
    for (int i = 0; i < kpm_area_count; i++) {
        if (kpm_areas[i].start == start) {
            kpm_areas[i] = kpm_areas[--kpm_area_count];   /* 末元素填补 */
            return;
        }
    }
}

int is_kpm_area(unsigned long addr)
{
    for (int i = 0; i < kpm_area_count; i++) {
        if (addr >= kpm_areas[i].start && addr < kpm_areas[i].end)
            return 1;
    }
    return 0;
}

/* =========================================================================
 * CFI bypass
 *
 * backup__cfi_slowpath / backup_report_cfi_failure 由 do_hook 写入
 *（原函数重定位后的指令序列地址，调用它 = 调原函数）。
 * ========================================================================= */
static unsigned long cached_cfi_slowpath = 0;
static unsigned long cached_report_cfi_failure = 0;

static cfi_slowpath_fn backup__cfi_slowpath = 0;
static enum bug_trap_type (*backup_report_cfi_failure)(struct pt_regs *,
    unsigned long addr, unsigned long *target, u32 type) = 0;

/* 目标在 KPM 区域或 hook thunk 区域 → 放行（这两类代码没有匹配的 CFI
 * 类型 hash，强行检查必然失败）。其它目标交给内核原函数。 */
static int should_cfi_pass(unsigned long target)
{
    return is_kpm_area(target) || is_thunk_area(target);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void replace__cfi_slowpath(u64 id, void *ptr, void *diag)
{
    if (should_cfi_pass((unsigned long)ptr))
        return;
    if (backup__cfi_slowpath)
        backup__cfi_slowpath(id, ptr, diag);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static enum bug_trap_type replace_report_cfi_failure(struct pt_regs *regs,
    unsigned long addr, unsigned long *target, u32 type)
{
    if (target && should_cfi_pass(*target))
        return BUG_TRAP_TYPE_WARN;
    if (backup_report_cfi_failure)
        return backup_report_cfi_failure(regs, addr, target, type);
    return BUG_TRAP_TYPE_WARN;
}

void cfi_bypass_init(void)
{
    cached_cfi_slowpath = kallsyms_lookup("__cfi_slowpath");
    if (!cached_cfi_slowpath)
        cached_cfi_slowpath = kallsyms_lookup("__cfi_slowpath_diag");
    cached_report_cfi_failure = kallsyms_lookup("report_cfi_failure");

    if (cached_report_cfi_failure) {
        long err = do_hook((void *)cached_report_cfi_failure,
                          (void *)replace_report_cfi_failure,
                          (void **)&backup_report_cfi_failure);
        if (err)
            klog("kpm_loader: hook report_cfi_failure at %llx failed: %ld\n",
                 (u64)cached_report_cfi_failure, err);
        else
            klog("kpm_loader: hooked report_cfi_failure at %llx\n",
                 (u64)cached_report_cfi_failure);
    }

    if (cached_cfi_slowpath) {
        long err = do_hook((void *)cached_cfi_slowpath,
                          (void *)replace__cfi_slowpath,
                          (void **)&backup__cfi_slowpath);
        if (err)
            klog("kpm_loader: hook __cfi_slowpath at %llx failed: %ld\n",
                 (u64)cached_cfi_slowpath, err);
        else
            klog("kpm_loader: hooked __cfi_slowpath at %llx\n",
                 (u64)cached_cfi_slowpath);
    }

    if (!cached_cfi_slowpath && !cached_report_cfi_failure)
        klog("kpm_loader: no CFI symbols found, bypass disabled\n");
}

void cfi_bypass_exit(void)
{
    if (backup_report_cfi_failure) {
        do_unhook((void *)cached_report_cfi_failure);
        backup_report_cfi_failure = 0;
    }
    if (backup__cfi_slowpath) {
        do_unhook((void *)cached_cfi_slowpath);
        backup__cfi_slowpath = 0;
    }
}
