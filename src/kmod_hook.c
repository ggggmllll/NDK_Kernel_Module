/*
 * kmod_hook.c — ARM64 inline hook engine
 *
 * 基于 KernelPatch kernel/base/hook.c（loader.c Section 8 提取）。
 * trampoline 统一 vmalloc + set_memory_x（去掉了原 loader 的 KPM text page
 * 复用优化，因为本模板不加载 KPM）。
 *
 * 依赖 kmod_kernel 的 patch 基础设施（patch_insn / call_set_memory_x /
 * call_stop_machine / kmod_patch_init 之后可用）。
 */

#include "kmod_hook.h"
#include "kmod_kernel.h"
#include "kmod_string.h"

/* ---- ARM64 指令 / 工具宏 ---- */
#define ARM64_NOP      0xd503201f
#define ARM64_BTI_C    0xd503245f
#define ARM64_BTI_J    0xd503249f
#define ARM64_BTI_JC   0xd50324df
#define ARM64_PACIASP  0xd503233f
#define ARM64_PACIBSP  0xd503237f

/* PAC 剥离：内核 VA 高位 0xFF，PAC 在 54..48；算术左移再右移符号扩展。 */
#define STRIP_PAC(ptr) ((void *)(((long)(ptr) << 8) >> 8))

#define TRAMPOLINE_MAX    6
#define RELOCATE_MAX      (4 * 8 + 4)
#define HOOK_REGION_SLOTS 32

/* PC-relative 指令类型 */
#define INST_B          0x14000000
#define INST_BC         0x54000000
#define INST_BL         0x94000000
#define INST_ADR        0x10000000
#define INST_ADRP       0x90000000
#define INST_LDR_32     0x18000000
#define INST_LDR_64     0x58000000
#define INST_LDRSW      0x98000000
#define INST_PRFM       0xD8000000
#define INST_LDR_SIMD32 0x1C000000
#define INST_LDR_SIMD64 0x5C000000
#define INST_LDR_SIMD128 0x9C000000
#define INST_CBZ        0x34000000
#define INST_CBNZ       0x35000000
#define INST_TBZ        0x36000000
#define INST_TBNZ       0x37000000
#define INST_IGNORE     0x0

#define MASK_B          0xFC000000
#define MASK_BC         0xFF000010
#define MASK_BL         0xFC000000
#define MASK_ADR        0x9F000000
#define MASK_ADRP       0x9F000000
#define MASK_LDR_32     0xFF000000
#define MASK_LDR_64     0xFF000000
#define MASK_LDRSW      0xFF000000
#define MASK_PRFM       0xFF000000
#define MASK_LDR_SIMD32 0xFF000000
#define MASK_LDR_SIMD64 0xFF000000
#define MASK_LDR_SIMD128 0xFF000000
#define MASK_CBZ        0x7F000000u
#define MASK_CBNZ       0x7F000000u
#define MASK_TBZ        0x7F000000u
#define MASK_TBNZ       0x7F000000u
#define MASK_IGNORE     0xFFFFF01F   /* HINT: PACIA/PACIB/SCS/BTI/NOP */

/* ---- hook_t / slot ---- */
typedef struct {
    u64 func_addr;
    u64 origin_addr;
    u64 replace_addr;
    u64 relo_addr;
    s32 tramp_insts_num;
    s32 relo_insts_num;
    u32 origin_insts[TRAMPOLINE_MAX];
    u32 tramp_insts[TRAMPOLINE_MAX];
    u32 *relo_insts;
    void *relo_alloc;
    unsigned long relo_alloc_size;
} hook_t;

typedef struct hook_mem_slot {
    int used;
    hook_t hook;
} hook_mem_slot_t;

static hook_mem_slot_t hook_slots[HOOK_REGION_SLOTS];

#define bits32(n, high, low) ((u32)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define sign64_extend(n, len) \
    (((u64)((u64)(n) << (63u - ((len) - 1))) >> 63u) ? ((u64)(n) | (0xFFFFFFFFFFFFFFFFULL << (len))) : (u64)(n))

static const u32 hook_masks[] = {
    MASK_B, MASK_BC, MASK_BL, MASK_ADR, MASK_ADRP,
    MASK_LDR_32, MASK_LDR_64, MASK_LDRSW, MASK_PRFM,
    MASK_LDR_SIMD32, MASK_LDR_SIMD64, MASK_LDR_SIMD128,
    MASK_CBZ, MASK_CBNZ, MASK_TBZ, MASK_TBNZ,
    MASK_IGNORE, 0
};
static const u32 hook_types[] = {
    INST_B, INST_BC, INST_BL, INST_ADR, INST_ADRP,
    INST_LDR_32, INST_LDR_64, INST_LDRSW, INST_PRFM,
    INST_LDR_SIMD32, INST_LDR_SIMD64, INST_LDR_SIMD128,
    INST_CBZ, INST_CBNZ, INST_TBZ, INST_TBNZ,
    INST_IGNORE, INST_IGNORE
};
static const s32 relo_lens[] = { 6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2, 2 };

/* ---- 分支链 / trampoline 地址工具 ---- */
static u64 branch_func_addr(u64 addr)
{
    for (;;) {
        u32 inst = *(u32 *)addr;
        if ((inst & MASK_B) == INST_B) {
            u64 imm26 = bits32(inst, 25, 0);
            addr = addr + sign64_extend(imm26 << 2u, 28u);
        } else if (inst == ARM64_BTI_C || inst == ARM64_BTI_J || inst == ARM64_BTI_JC) {
            addr += 4;
        } else {
            break;
        }
    }
    return addr;
}

static int is_in_tramp(hook_t *hook, u64 addr)
{
    u64 start = hook->origin_addr;
    u64 end = start + hook->tramp_insts_num * 4;
    return addr >= start && addr < end;
}

static u64 relo_in_tramp(hook_t *hook, u64 addr)
{
    u64 start = hook->origin_addr;
    if (!(addr >= start && addr < start + hook->tramp_insts_num * 4))
        return addr;

    u32 inst_idx = (addr - start) / 4;
    u64 fix = hook->relo_addr;
    for (u32 i = 0; i < inst_idx; i++) {
        u32 inst = hook->origin_insts[i];
        for (int j = 0; j < (int)ARRAY_SIZE(relo_lens); j++) {
            if ((inst & hook_masks[j]) == hook_types[j]) {
                fix += relo_lens[j] * 4;
                break;
            }
        }
    }
    return fix;
}

/* 绝对跳转：LDR X17,#8; BR X17; .quad target（4 条指令）*/
static s32 branch_absolute(u32 *buf, u64 addr)
{
    buf[0] = 0x58000051;
    buf[1] = 0xD61F0220;
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}

static s32 branch_from_to(u32 *buf, u64 src, u64 dst)
{
    (void)src;
    return branch_absolute(buf, dst);
}

/* ---- PC-relative 指令重定位 ---- */
static int relo_b(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u64 addr;

    if (type == INST_BC) {
        addr = inst_addr + sign64_extend(bits32(inst, 23, 5) << 2u, 21u);
    } else {
        addr = inst_addr + sign64_extend(bits32(inst, 25, 0) << 2u, 28u);
    }
    addr = relo_in_tramp(hook, addr);

    u32 idx = 0;
    if (type == INST_BC) {
        buf[idx++] = (inst & 0xFF00001F) | 0x40u;
        buf[idx++] = 0x14000006;
    }
    buf[idx++] = 0x58000051;
    buf[idx++] = 0x14000003;
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E;
        buf[idx++] = 0x910033DE;
        buf[idx++] = 0xD65F0220;
    } else {
        buf[idx++] = 0xD65F0220;
    }
    buf[idx++] = ARM64_NOP;
    return 0;
}

static int relo_adr(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u32 xd = bits32(inst, 4, 0);
    u64 immlo = bits32(inst, 30, 29);
    u64 immhi = bits32(inst, 23, 5);
    u64 addr;

    if (type == INST_ADR) {
        addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
    } else {
        addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & ~0xfffULL;
        if (is_in_tramp(hook, addr)) return -1;
    }

    buf[0] = 0x58000040u | xd;
    buf[1] = 0x14000003;
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 0;
}

static int relo_ldr(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u32 rt = bits32(inst, 4, 0);
    u64 offset = sign64_extend(bits32(inst, 23, 5) << 2u, 21u);
    u64 addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM) return -1;
    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW) {
        buf[0] = 0x58000060u | rt;
        if (type == INST_LDR_32)
            buf[1] = 0xB9400000 | rt | (rt << 5u);
        else if (type == INST_LDR_64)
            buf[1] = 0xF9400000 | rt | (rt << 5u);
        else
            buf[1] = 0xB9800000 | rt | (rt << 5u);
        buf[2] = 0x14000004;
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        buf[0] = 0xA93F47F0;
        buf[1] = 0x58000091;
        if (type == INST_PRFM)
            buf[2] = 0xF9800220 | rt;
        else if (type == INST_LDR_SIMD32)
            buf[2] = 0xBD400220 | rt;
        else if (type == INST_LDR_SIMD64)
            buf[2] = 0xFD400220 | rt;
        else
            buf[2] = 0x3DC00220u | rt;
        buf[3] = 0xF85F83F1;
        buf[4] = 0x14000004;
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return 0;
}

static int relo_cb(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    (void)type;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u64 addr = inst_addr + sign64_extend(bits32(inst, 23, 5) << 2u, 21u);
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u;
    buf[1] = 0x14000005;
    buf[2] = 0x58000051;
    buf[3] = 0xD65F0220;
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return 0;
}

static int relo_tb(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    (void)type;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u64 addr = inst_addr + sign64_extend(bits32(inst, 18, 5) << 2u, 16u);
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u;
    buf[1] = 0x14000005;
    buf[2] = 0x58000051;
    buf[3] = 0xD61F0220;   /* BR X17（tbz 用 X17 做 scratch，不能 RET）*/
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return 0;
}

static int relo_ignore(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    (void)inst_addr; (void)type;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return 0;
}

static int relocate_inst(hook_t *hook, u64 inst_addr, u32 inst)
{
    s32 len = 2;
    u32 it = INST_IGNORE;

    for (int j = 0; j < (int)ARRAY_SIZE(relo_lens); j++) {
        if ((inst & hook_masks[j]) == hook_types[j]) {
            it = hook_types[j];
            len = relo_lens[j];
            break;
        }
    }

    int rc = 0;
    switch (it) {
    case INST_B:  case INST_BC: case INST_BL:
        rc = relo_b(hook, inst_addr, inst, it); break;
    case INST_ADR: case INST_ADRP:
        rc = relo_adr(hook, inst_addr, inst, it); break;
    case INST_LDR_32: case INST_LDR_64: case INST_LDRSW:
    case INST_PRFM: case INST_LDR_SIMD32: case INST_LDR_SIMD64: case INST_LDR_SIMD128:
        rc = relo_ldr(hook, inst_addr, inst, it); break;
    case INST_CBZ: case INST_CBNZ:
        rc = relo_cb(hook, inst_addr, inst, it); break;
    case INST_TBZ: case INST_TBNZ:
        rc = relo_tb(hook, inst_addr, inst, it); break;
    default:
        rc = relo_ignore(hook, inst_addr, inst, it); break;
    }
    hook->relo_insts_num += len;
    return rc;
}

/* ---- slot 管理 ---- */
static hook_t *hook_alloc(u64 origin_addr)
{
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (!hook_slots[i].used) {
            unsigned long exec_size = PAGE_SIZE;
            void *exec_mem = vmalloc(exec_size);
            if (!exec_mem) return NULL;
            memset(exec_mem, 0, exec_size);

            hook_slots[i].used = 1;
            memset(&hook_slots[i].hook, 0, sizeof(hook_t));
            hook_slots[i].hook.origin_addr = origin_addr;
            /* relo_insts[0] 在偏移 +4；-4..0 留给 kCFI hash */
            hook_slots[i].hook.relo_insts = (u32 *)((char *)exec_mem + 4);
            hook_slots[i].hook.relo_alloc = exec_mem;
            hook_slots[i].hook.relo_alloc_size = exec_size;
            return &hook_slots[i].hook;
        }
    }
    return NULL;
}

static hook_t *hook_find(u64 origin_addr)
{
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (hook_slots[i].used && hook_slots[i].hook.origin_addr == origin_addr)
            return &hook_slots[i].hook;
    }
    return NULL;
}

static void hook_free(hook_t *hook)
{
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (&hook_slots[i].hook == hook) {
            if (hook->relo_alloc) vfree(hook->relo_alloc);
            hook_slots[i].used = 0;
            return;
        }
    }
}

/* ---- 准备 trampoline ---- */
static int hook_prepare(hook_t *hook)
{
    for (int i = 0; i < TRAMPOLINE_MAX; i++)
        hook->origin_insts[i] = *((u32 *)hook->origin_addr + i);

    u32 first = hook->origin_insts[0];
    int is_bti = (first == ARM64_BTI_C || first == ARM64_BTI_J || first == ARM64_BTI_JC);
    int is_pac = (first == ARM64_PACIASP || first == ARM64_PACIBSP);

    if (is_bti || is_pac) {
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num = 1 + branch_from_to(&hook->tramp_insts[1],
                                                    hook->origin_addr, hook->replace_addr);
    } else {
        hook->tramp_insts_num = branch_from_to(hook->tramp_insts,
                                               hook->origin_addr, hook->replace_addr);
    }

    for (int i = 0; i < RELOCATE_MAX; i++)
        hook->relo_insts[i] = ARM64_NOP;

    hook->relo_insts[0] = ARM64_BTI_JC;
    hook->relo_insts[1] = ARM64_NOP;
    hook->relo_insts_num = 2;

    for (int i = 0; i < hook->tramp_insts_num; i++) {
        u64 inst_addr = hook->origin_addr + i * 4;
        u32 inst = hook->origin_insts[i];
        if (relocate_inst(hook, inst_addr, inst) < 0)
            return -1;
    }

    /* 跳回原函数 trampoline 之后 */
    u64 back_src = hook->relo_addr + hook->relo_insts_num * 4;
    u64 back_dst = hook->origin_addr + hook->tramp_insts_num * 4;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src, back_dst);

    /* 复制 kCFI hash 到 relo_insts[-1]，让 backup 指针过 CFI */
    if (hook->origin_addr > 4 && (hook->origin_addr & 0xFFF) >= 4) {
        u32 cfi_hash = *(u32 *)(hook->origin_addr - 4);
        if (cfi_hash && cfi_hash != 0xFFFFFFFF)
            *(u32 *)((u8 *)hook->relo_insts - 4) = cfi_hash;
    }

    /* trampoline 可执行 + 刷 I-cache */
    if (hook->relo_alloc) {
        int np = (int)((hook->relo_alloc_size + PAGE_SIZE - 1) / PAGE_SIZE);
        call_set_memory_x((unsigned long)hook->relo_alloc, np);
        call_flush_icache((unsigned long)hook->relo_alloc,
                          (unsigned long)hook->relo_alloc + hook->relo_alloc_size);
    }
    return 0;
}

/* ---- install / uninstall ---- */
static void hook_install(hook_t *hook)
{
    for (int i = 0; i < hook->tramp_insts_num; i++) {
        u32 *addr = (u32 *)hook->origin_addr + i;
        patch_insn(addr, hook->tramp_insts[i]);
    }
}

static void hook_uninstall(hook_t *hook)
{
    for (int i = 0; i < hook->tramp_insts_num; i++) {
        u32 *addr = (u32 *)hook->origin_addr + i;
        patch_insn(addr, hook->origin_insts[i]);
    }
}

/* stop_machine callback：所有 CPU 停时装 hook，消除竞态。
 * 设 g_in_stop_machine 让 patch_insn 跳过 nested stop_machine/synchronize_rcu。 */
static int hook_install_stop_cb(void *data)
{
    hook_t *hook = data;
    patch_set_in_stop_machine(1);
    hook_install(hook);
    patch_set_in_stop_machine(0);
    return 0;
}

/* ---- 对外 API ---- */
long do_hook(void *func, void *replace, void **backup)
{
    if (!func || !replace || !backup) return -1;

    func = STRIP_PAC(func);
    replace = STRIP_PAC(replace);

    u64 origin = branch_func_addr((u64)func);
    hook_t *hook = hook_alloc(origin);
    if (!hook) return -1;

    hook->func_addr = (u64)func;
    hook->replace_addr = (u64)replace;
    hook->relo_addr = (u64)hook->relo_insts;

    int err = hook_prepare(hook);
    if (err) { hook_free(hook); return err; }

    if (call_stop_machine(hook_install_stop_cb, hook) < 0)
        hook_install(hook);   /* stop_machine 不可用，直接装 */
    *backup = STRIP_PAC((void *)hook->relo_addr);

    if (klog)
        klog("kmod_hook: hooked func %llx -> %llx\n",
             (unsigned long long)hook->func_addr, (unsigned long long)hook->replace_addr);
    return 0;
}

void do_unhook(void *func)
{
    if (!func) return;
    func = STRIP_PAC(func);

    /* 直接按 func 查（不能用 branch_func_addr——hook 装上后入口已变 B 跳转，
     * branch_func_addr 会跟进去返回 trampoline 地址）。*/
    hook_t *hook = hook_find((u64)func);
    if (!hook) hook = hook_find(branch_func_addr((u64)func));
    if (!hook) return;

    hook_uninstall(hook);
    hook_free(hook);

    if (klog)
        klog("kmod_hook: unhooked func %llx\n", (unsigned long long)(u64)func);
}

/* =========================================================================
 * 第二阶段：wrap hook（before/after 回调）+ syscall hook
 *
 * 基于 KernelPatch 的 thunk 池：每次 hook_wrap 分配一个 32 字节 thunk，
 *   ldr x9, chain ; ldr x16, dispatch ; br x16
 * dispatch_main 收到后构建 hook_fargs_t（x0–x7 + chain），依次调
 * before → backup(原函数) → after，返回 ret。
 *
 * 从 loader.c Section 8b 提取，去 kp_ 前缀；剥离 is_kpm_area / local_sym
 *（不加载 KPM，不需 KPM 区域 CFI 放行，也不导出符号表给 KPM）。
 * ========================================================================= */

#define CHAIN_NUM  8
#define THUNK_SIZE 32

/* chain 结构：前 24 字节占位对齐 hook_t（兼容 KP 的 wrap_get_origin_func
 * 读 offset 24 = backup）。*/
typedef struct {
    u64 _pad0, _pad1, _pad2;
    u64 backup;                 /* +24 */
    void *before, *after, *udata;
    int argno, occupied;
    u32 *thunk;
    void *original_func;
    u32 cfi_hash;
} chain_t;

/* thunk 模板：ldr x9,#16 ; ldr x16,#20 ; br x16 ; nop ; .quad chain ; .quad dispatch */
static const u32 thunk_tmpl[8] = {
    0x58000089,  /* ldr x9, #16  */
    0x580000B0,  /* ldr x16, #20 */
    0xD61F0200,  /* br x16       */
    0xD503201F,  /* nop          */
    0, 0,        /* chain ptr    */
    0, 0,        /* dispatch addr*/
};

static chain_t chains[CHAIN_NUM];
static u32 *thunk_addrs[CHAIN_NUM];

/* 判断地址是否落在某个 hook thunk 页内。
 * cfi_bypass 用：thunk 区域的间接调用也跳过 CFI 检查。
 * thunk 在 vmalloc 页内，按页对齐判断。 */
int is_thunk_area(unsigned long addr)
{
    for (int i = 0; i < CHAIN_NUM; i++) {
        if (!thunk_addrs[i]) continue;
        unsigned long start = (unsigned long)thunk_addrs[i] & ~(PAGE_SIZE - 1);
        if (addr >= start && addr < start + PAGE_SIZE)
            return 1;
    }
    return 0;
}

/* syscall hook 状态（文件 static，不导出）*/
static int has_syscall_wrapper = 0;
static unsigned long sys_call_table_addr = 0;

/* ---- dispatch：thunk br x16 进入，x9 = chain 指针 ----
 * hook_fargs_t 布局（KernelPatch 兼容）：
 *   +0  chain (void*)
 *   +8  skip_origin(int32) + padding
 *   +16 local (8 × u64)
 *   +80 ret (u64)
 *   +88 args[0..7] (u64 each)
 * 共 152 字节，这里开 160 对齐。*/
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi"), noinline))
static u64 dispatch_main(u64 a0, u64 a1, u64 a2, u64 a3,
                         u64 a4, u64 a5, u64 a6, u64 a7)
{
    chain_t *chain;
    asm volatile("mov %0, x9" : "=r"(chain));
    if (!chain || !chain->occupied) return 0;

    u8 fargs_buf[160] __attribute__((aligned(8)));
    u64 *fp = (u64 *)fargs_buf;
    for (int i = 0; i < 20; i++) ((volatile unsigned long *)fargs_buf)[i] = 0;

    fp[0]  = (u64)chain;
    fp[10] = a0;            /* ret 占位 */
    fp[11] = a0; fp[12] = a1; fp[13] = a2; fp[14] = a3;
    fp[15] = a4; fp[16] = a5; fp[17] = a6; fp[18] = a7;
    void *fargs = fargs_buf;

    if (chain->before) {
        typedef void (*fn_t)(void *, void *);
        ((fn_t)chain->before)(fargs, chain->udata);
    }

    /* 调原函数（backup）。用 register asm 保证参数在 x0–x7。*/
    u64 ret;
    {
        register u64 r0 asm("x0") = a0;
        register u64 r1 asm("x1") = a1;
        register u64 r2 asm("x2") = a2;
        register u64 r3 asm("x3") = a3;
        register u64 r4 asm("x4") = a4;
        register u64 r5 asm("x5") = a5;
        register u64 r6 asm("x6") = a6;
        register u64 r7 asm("x7") = a7;
        u64 (*backup_fn)(u64, u64, u64, u64, u64, u64, u64, u64) =
            (typeof(backup_fn))chain->backup;
        asm volatile(
            "blr %8\n"
            : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3),
              "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7)
            : "r"(backup_fn)
            : "x8","x9","x10","x11","x12","x13","x14","x15",
              "x16","x17","x30","memory"
        );
        ret = r0;
    }
    fp[10] = ret;

    if (chain->after) {
        typedef void (*fn_t)(void *, void *);
        ((fn_t)chain->after)(fargs, chain->udata);
    }
    return fp[10];
}

/* ---- thunk 池 ---- */
static int thunk_alloc(chain_t *chain)
{
    for (int i = 0; i < CHAIN_NUM; i++) {
        if (!thunk_addrs[i]) {
            void *mem = vmalloc(PAGE_SIZE);
            if (!mem) return -1;
            memset(mem, 0, PAGE_SIZE);

            /* thunk 放 mem+8，kCFI hash 放 mem+4（=thunk-4，同 vmalloc 页）*/
            u32 *thunk = (u32 *)((u8 *)mem + 8);
            *(u32 *)(thunk - 1) = chain->cfi_hash;
            __builtin_memcpy(thunk, thunk_tmpl, THUNK_SIZE);
            *(u64 *)(thunk + 4) = (u64)chain;
            *(u64 *)(thunk + 6) = (u64)&dispatch_main;

            call_set_memory_x((unsigned long)mem, 1);
            call_flush_icache((unsigned long)thunk,
                              (unsigned long)thunk + THUNK_SIZE);

            thunk_addrs[i] = thunk;
            chain->thunk = thunk;
            return i;
        }
    }
    return -1;
}

static void thunk_free(int idx)
{
    if (idx >= 0 && idx < CHAIN_NUM && thunk_addrs[idx]) {
        void *page = (void *)((unsigned long)thunk_addrs[idx] & ~(PAGE_SIZE - 1));
        vfree(page);
        thunk_addrs[idx] = 0;
    }
    if (idx >= 0 && idx < CHAIN_NUM) {
        chains[idx].thunk = 0;
        chains[idx].occupied = 0;
    }
}

/* ---- wrap hook（对外）---- */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
long hook_wrap(void *func, int argno, void *before, void *after, void *udata)
{
    if (!func) return -4095;   /* HOOK_BAD_ADDRESS */
    func = STRIP_PAC(func);

    /* 已 hook 同一函数：替换 before/after */
    for (int i = 0; i < CHAIN_NUM; i++) {
        if (chains[i].occupied && chains[i].original_func == func) {
            chains[i].before = before;
            chains[i].after  = after;
            chains[i].udata  = udata;
            chains[i].argno  = argno;
            return 0;
        }
    }

    int slot = -1;
    for (int i = 0; i < CHAIN_NUM; i++) {
        if (!chains[i].occupied) { slot = i; break; }
    }
    if (slot < 0) return -4093;   /* HOOK_NO_MEM */

    chain_t *chain = &chains[slot];
    memset(chain, 0, sizeof(*chain));
    chain->before = before;
    chain->after  = after;
    chain->udata  = udata;
    chain->argno  = argno;
    chain->original_func = func;

    int tidx = thunk_alloc(chain);
    if (tidx < 0) return -4093;

    void *backup = 0;
    long err = do_hook(func, (void *)chain->thunk, &backup);
    if (err) { thunk_free(tidx); return -4092; }   /* HOOK_BAD_RELO */

    chain->backup = (u64)STRIP_PAC(backup);
    chain->occupied = 1;
    return 0;
}

void unhook(void *func)
{
    if (!func) return;
    func = STRIP_PAC(func);

    for (int i = 0; i < CHAIN_NUM; i++) {
        if (chains[i].occupied && chains[i].original_func == func) {
            do_unhook(func);
            thunk_free(i);
            return;
        }
    }
    do_unhook(func);   /* fallback：非 chain 的 one-shot hook */
}

/* ---- syscall hook ---- */
static int syscall_hook_init(void)
{
    if (sys_call_table_addr) return 0;
    sys_call_table_addr = kallsyms_lookup("sys_call_table");
    if (!sys_call_table_addr) {
        if (klog) klog("kmod_hook: cannot find sys_call_table\n");
        return -1;
    }
    /* has_syscall_wrapper：GKI 5.10+ 用 CONFIG_ARM64_SYSCALL_WRAPPER，
     * 通过是否存在 __arm64_sys_openat 判断。*/
    if (kallsyms_lookup("__arm64_sys_openat"))
        has_syscall_wrapper = 1;
    if (klog)
        klog("kmod_hook: sys_call_table=%llx wrapper=%d\n",
             (unsigned long long)sys_call_table_addr, has_syscall_wrapper);
    return 0;
}

static u64 syscall_addr(int nr)
{
    if (!sys_call_table_addr || nr < 0) return 0;
    unsigned long *table = (unsigned long *)sys_call_table_addr;
    return (u64)table[nr];
}

/* 函数指针 hook：改 sys_call_table[nr] 指向 thunk。sys_call_table 是
 * __ro_after_init，set_memory_rw 够不着，用 write_kernel_u64 走 PTE。*/
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
long fp_wrap_syscalln(int nr, int narg, int is_compat,
                      void *before, void *after, void *udata)
{
    (void)is_compat;
    if (syscall_hook_init() != 0) return -4095;

    u64 fp_addr = sys_call_table_addr + (u64)nr * sizeof(unsigned long);
    u64 origin_syscall = syscall_addr(nr);
    if (!origin_syscall) return -4095;

    int slot = -1;
    for (int i = 0; i < CHAIN_NUM; i++) {
        if (!chains[i].occupied) { slot = i; break; }
    }
    if (slot < 0) return -4093;

    chain_t *chain = &chains[slot];
    memset(chain, 0, sizeof(*chain));
    chain->before = before;
    chain->after  = after;
    chain->udata  = udata;
    chain->argno  = narg;
    chain->original_func = (void *)fp_addr;   /* 标记：FP hook */
    chain->backup  = origin_syscall;

    /* 复制 kCFI hash 让 thunk 过 CFI */
    if (origin_syscall > 4 && (origin_syscall & 0xFFF) >= 4)
        chain->cfi_hash = *(u32 *)(origin_syscall - 4);

    int tidx = thunk_alloc(chain);
    if (tidx < 0) return -4093;

    write_kernel_u64((u64 *)fp_addr, (u64)chain->thunk);
    chain->occupied = 1;
    return 0;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    (void)is_compat; (void)before; (void)after;
    if (!sys_call_table_addr || nr < 0) return;
    u64 fp_addr = sys_call_table_addr + (u64)nr * sizeof(unsigned long);
    for (int i = 0; i < CHAIN_NUM; i++) {
        if (chains[i].occupied && chains[i].original_func == (void *)fp_addr) {
            write_kernel_u64((u64 *)fp_addr, chains[i].backup);
            thunk_free(i);
            return;
        }
    }
}

/* inline hook：直接 hook syscall handler 函数入口。*/
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
long inline_wrap_syscalln(int nr, int narg, int is_compat,
                          void *before, void *after, void *udata)
{
    (void)is_compat;
    if (syscall_hook_init() != 0) return -4095;
    u64 syscall_func = syscall_addr(nr);
    if (!syscall_func) return -4095;
    return hook_wrap((void *)syscall_func, narg, before, after, udata);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    (void)is_compat; (void)before; (void)after;
    if (!sys_call_table_addr || nr < 0) return;
    u64 syscall_func = syscall_addr(nr);
    if (!syscall_func) return;
    unhook((void *)syscall_func);
}

/* =========================================================================
 * 自定义 syscall 注册（占用 sys_call_table slot）
 * ========================================================================= */

int syscall_slot_status(int nr)
{
    if (syscall_hook_init() != 0) return KMOD_SYSCALL_SLOT_UNKNOWN;
    if (nr < 0) return KMOD_SYSCALL_SLOT_UNKNOWN;
    unsigned long *slot = (unsigned long *)sys_call_table_addr + nr;
    unsigned long orig = *slot;
    if (orig == 0) return KMOD_SYSCALL_SLOT_EMPTY;
    if ((orig & 0xFFF) == 0) return KMOD_SYSCALL_SLOT_GARBAGE;
    return KMOD_SYSCALL_SLOT_USED;
}

long register_syscall(int nr, void *handler, u64 *prefix)
{
    if (syscall_hook_init() != 0) return -1;
    if (nr < 0) return -1;

    unsigned long *slot = (unsigned long *)sys_call_table_addr + nr;
    unsigned long orig = *slot;

    /* patch sys_call_table[nr] → handler（走 PTE，sys_call_table 是 __ro_after_init）*/
    write_kernel_u64((u64 *)slot, (u64)handler);

    /* 偷原 handler 的 kCFI hash 写进我们的 prefix（6.x wrapper 内核，
     * invoke_syscall 对 handler 做 ldr w16,[x16,#-4] 检查）。prefix 是 8 字节
     * 占位，hash 写在高 4 字节（= handler-4）。orig 不在用则偷不到，跳过。*/
    if (has_syscall_wrapper && orig > 4 && (orig & 0xFFF) >= 4 && prefix) {
        u32 cfi_hash = *(u32 *)(orig - 4);
        write_kernel_u64(prefix, (u64)cfi_hash << 32);
        if (klog)
            klog("kmod_hook: patched kCFI hash %08x for syscall[%d]\n",
                 cfi_hash, nr);
    }

    if (klog)
        klog("kmod_hook: registered syscall[%d] orig=%llx handler=%llx\n",
             nr, (unsigned long long)orig, (unsigned long long)handler);
    return (long)orig;
}

void unregister_syscall(int nr, unsigned long orig)
{
    if (!sys_call_table_addr || nr < 0) return;
    unsigned long *slot = (unsigned long *)sys_call_table_addr + nr;
    write_kernel_u64((u64 *)slot, orig);
    if (klog)
        klog("kmod_hook: unregistered syscall[%d] → restored %llx\n",
             nr, (unsigned long long)orig);
}
