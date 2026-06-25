/*
 * kmod_kernel.c — kmod_kernel.h 的实现
 *   - kallsyms 基础设施 + printk 解析
 *   - patch 基础设施：call_* wrappers + pgtable + patch_insn
 *
 * 库文件，CMake 编译一次，多 .c 模块链接共享。
 */

#include "kmod_kernel.h"
#include "kmod_kcfi.h"

/* ==================== klog + kallsyms 基础设施 ==================== */
void (*klog)(const char *fmt, ...) = 0;

static unsigned long (*volatile kallsyms_lookup_name_fn)(const char *name) = 0;

/* fixup_ko 按字符串扫描 .ko 找 marker，不依赖符号导出 —— 所以 static。 */
static struct {
    char marker[32];               /* 正好 32 字节，地址在 8 字节对齐的偏移 32 */
    volatile unsigned long addr;
} kallsyms_patch __attribute__((aligned(8), used)) = {
    "KPM_KALLSYMS_NAME_PATCH_SLOT_V1X",
    0
};

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void __cfi_slowpath(u64 id, void *ptr, void *diag)
{
    (void)id; (void)ptr; (void)diag;
}

__attribute__((no_sanitize("cfi")))
void resolve_printk(void)
{
    if (klog) return;
    if (!kallsyms_lookup_name_fn) return;
    unsigned long addr = kallsyms_lookup_name_fn("printk");
    if (!addr) addr = kallsyms_lookup_name_fn("_printk");
    if (addr) klog = (typeof(klog))addr;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long strat_kprobe_kallsyms(void)
{
    if (!register_kprobe) return 0;   /* not exported on this kernel (e.g. 4.19 prod) */
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    int rc = register_kprobe(&kp);
    if (rc < 0) return 0;
    unsigned long addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

#define KSYM_NAME_LEN 128
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long strat_sprintf_scan(void)
{
    extern int snprintf(char *buf, unsigned long size, const char *fmt, ...);
    char buf[KSYM_NAME_LEN];

    unsigned long kaddr = (unsigned long)vfree;
    kaddr &= 0xffffffffff000000;
    for (int i = 0; i < 0x200000; i++) {
        snprintf(buf, sizeof(buf), "%ps", (void *)kaddr);
        if (strncmp(buf, "kallsyms_lookup_name", 20) == 0) return kaddr;
        kaddr += 0x10;
    }
    return 0;
}

__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long __kallsyms_lookup_named(const char *name)
{
    if (kallsyms_lookup_name_fn) return kallsyms_lookup_name_fn(name);
    return 0;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
unsigned long kallsyms_lookup(const char *name)
{
    return __kallsyms_lookup_named(name);
}

void kallsyms_init(void)
{
    unsigned long addr = 0;

    /* 策略顺序按【对 KASLR 的健壮性】排：运行期自解析优先，注入的 marker
     * 只作最后兜底。
     *
     * marker（kallsyms_patch.addr）是 fixup_ko 在【某次启动】按 /proc/kallsyms
     * 写死的绝对地址 —— KASLR 每次启动重随机化内核基址，跨重启复用必然指向
     * 错误/未映射地址，加载即崩。所以不能再把它放第一位无条件信任。
     *
     * kprobe / %ps 扫描都在【本次启动】实时求值，KASLR 免疫，开机即可用，
     * 无需 fixup。只有这两者都失败（内核裁了 kprobe、符号扫描没命中）才退回
     * marker，且仅当它落在内核地址空间才采用（挡掉陈旧的用户态/垃圾值）。 */

    /* 策略 1：kprobe（KASLR 免疫，无需 fixup） */
    addr = strat_kprobe_kallsyms();
    if (addr) { kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))addr; resolve_printk(); }

    /* 策略 2：%ps 扫描（KASLR 免疫，较慢但通用） */
    if (!kallsyms_lookup_name_fn) {
        addr = strat_sprintf_scan();
        if (addr) { kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))addr; resolve_printk(); }
    }

    /* 策略 3（兜底）：fixup_ko 注入的 marker —— 仅当上面都失败，且地址落在
     * 内核空间（高半 canonical）才用，避免跨重启的陈旧地址直接崩内核。 */
    if (!kallsyms_lookup_name_fn &&
        kallsyms_patch.addr >= 0xffff000000000000UL) {
        kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))kallsyms_patch.addr;
        resolve_printk();
    }
}

/* ==================== patch 基础设施 ==================== */
static unsigned long cached_module_alloc = 0;
static unsigned long cached_insn_patch = 0;
static unsigned long cached_flush_icache = 0;
static unsigned long cached_set_memory_x = 0;
static unsigned long cached_set_memory_rw = 0;
static unsigned long cached_stop_machine = 0;
static unsigned long cached_synchronize_rcu = 0;
static unsigned long cached_memstart_addr = 0;
static unsigned long cached_swapper_pg_dir = 0;
static unsigned long cached_printk_deferred = 0;

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void *call_module_alloc(unsigned long size)
{
    if (!cached_module_alloc) return 0;
    typedef void *(*fn_t)(unsigned long);
    return ((fn_t)cached_module_alloc)(size);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void call_flush_icache(unsigned long start, unsigned long end)
{
    if (!cached_flush_icache) return;
    typedef void (*fn_t)(unsigned long, unsigned long);
    ((fn_t)cached_flush_icache)(start, end);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
int call_set_memory_x(unsigned long addr, int numpages)
{
    if (!cached_set_memory_x) return -1;
    typedef int (*fn_t)(unsigned long, int);
    return ((fn_t)cached_set_memory_x)(addr, numpages);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
int call_set_memory_rw(unsigned long addr, int numpages)
{
    if (!cached_set_memory_rw) return -1;
    typedef int (*fn_t)(unsigned long, int);
    return ((fn_t)cached_set_memory_rw)(addr, numpages);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
int call_insn_patch(void *addr, u32 insn)
{
    if (!cached_insn_patch) return -1;
    typedef int (*fn_t)(void *, u32);
    return ((fn_t)cached_insn_patch)(addr, insn);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
int call_stop_machine(int (*fn)(void *), void *data)
{
    if (!cached_stop_machine) return -1;
    typedef int (*st_fn_t)(int (*)(void *), void *, const void *);
    return ((st_fn_t)cached_stop_machine)(fn, data, (const void *)0);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void call_synchronize_rcu(void)
{
    if (!cached_synchronize_rcu) return;
    typedef void (*fn_t)(void);
    ((fn_t)cached_synchronize_rcu)();
}

/* ---- 加锁场景日志（printk_deferred，经 irq_work 延迟，不抢 logbuf_lock）---- */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void klog_deferred(const char *fmt)
{
    if (!cached_printk_deferred) return;
    typedef void (*fn_t)(const char *fmt, ...);
    ((fn_t)cached_printk_deferred)(fmt);
}

/* ---- 内核态读文件 ----
 * 优先 read_iter（支持 kernel buffer，ITER_KVEC）；否则退到 f_op->read
 *（/proc 类文件，严格 PAN 内核可能失败）。*/
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
long kmod_read_file(struct file *filp, void *buf, unsigned long len, long long *pos)
{
    if (!filp || !filp->f_op) return 0;

    if (filp->f_op->read_iter) {
        char _kiocb[64];
        memset(_kiocb, 0, sizeof(_kiocb));
        struct kiocb *k = (struct kiocb *)_kiocb;
        k->ki_filp = filp;
        k->ki_pos = *pos;

        struct kvec iov = { .iov_base = buf, .iov_len = len };
        char _iter[128];
        memset(_iter, 0, sizeof(_iter));
        struct iov_iter *iter = (struct iov_iter *)_iter;

        iov_iter_kvec(iter, 0 /* READ */, &iov, 1, len);
        long ret = filp->f_op->read_iter(k, iter);
        if (ret > 0) *pos = k->ki_pos;
        return ret;
    }

    if (filp->f_op->read)
        return filp->f_op->read(filp, buf, len, pos);

    return 0;
}

/* ---- 读整个文件到 vmalloc 缓冲（共享封装）----
 * filp_open 懒解析（GKI 6.1 不导出）；成功返回 vmalloc 的数据指针并经
 * *out_size 回传长度（调用方用完 vfree）；失败返回 NULL。
 * max_size 限制读取上限（防异常大文件），传 0 表示用默认 16MB。 */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void *kmod_read_whole_file(const char *path, long *out_size, unsigned long max_size)
{
    static unsigned long fn_open = 0;
    static int tried = 0;
    if (out_size) *out_size = 0;
    if (!max_size) max_size = 16UL << 20;

    if (!tried) { fn_open = kallsyms_lookup("filp_open"); tried = 1; }
    if (!fn_open) return 0;
    typedef struct file *(*open_t)(const char *, int, int);
    struct file *filp = ((open_t)fn_open)(path, 0 /* O_RDONLY */, 0);
    if (!filp || (unsigned long)filp >= 0xfffffffffffff000UL) return 0;

    long long size = vfs_llseek(filp, 0, 2);   /* SEEK_END */
    if (size <= 0 || (unsigned long long)size > max_size) {
        filp_close(filp, 0);
        return 0;
    }
    void *data = vmalloc((unsigned long)size + 1);
    if (!data) { filp_close(filp, 0); return 0; }

    long long pos = 0;
    vfs_llseek(filp, 0, 0);                     /* SEEK_SET */
    long nread = kmod_read_file(filp, data, (unsigned long)size, &pos);
    filp_close(filp, 0);
    if (nread <= 0) { vfree(data); return 0; }

    ((char *)data)[nread] = '\0';               /* 便于文本解析 */
    if (out_size) *out_size = nread;
    return data;
}

/* ---- pgtable（文件 static）----
 * set_memory_rw 只对 vmalloc 页生效；__ro_after_init / rodata 要走页表。 */
#define PTE_VALID       (1UL << 0)
#define PTE_TYPE_BLOCK  (1UL << 0)
#define PTE_TYPE_TABLE  (3UL << 0)
#define PTE_ADDR_MASK   0x0000FFFFFFFFF000ULL
#define PTE_RDONLY      (1UL << 7)
#define PTE_DBM         (1UL << 51)

static int pgtable_ready = 0;
static u64 page_offset_v = 0;
static u64 phys_offset_v = 0;
static int page_levels = 3;

static void pgtable_lazy_init(void)
{
    if (pgtable_ready) return;
    u64 tcr;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    u64 t1sz = (tcr >> 16) & 0x3f;
    u64 va_bits = 64 - t1sz;
    page_offset_v = ~((1ULL << va_bits) - 1);
    if (cached_memstart_addr)
        phys_offset_v = *(u64 *)cached_memstart_addr;
    u64 pxd_bits = 12 - 3;
    page_levels = (int)((va_bits - 12 + pxd_bits - 1) / pxd_bits);
    pgtable_ready = 1;
}

static inline u64 __pa_to_va(u64 pa)
{
    return pa - phys_offset_v + page_offset_v;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static u64 *walk_kernel_pte(u64 va)
{
    pgtable_lazy_init();
    if (!pgtable_ready) return 0;
    u64 pxd_bits = 9;
    u64 pxd_ptrs = 512;

    u64 pxd_va = cached_swapper_pg_dir;
    if (!pxd_va) {
        u64 ttbr1;
        asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
        u64 pgd_pa = ttbr1 & ~0xFFFFULL;
        pxd_va = __pa_to_va(pgd_pa);
    }

    u64 leaf_entry_va = 0;
    for (int lv = 4 - page_levels; lv < 4; lv++) {
        u64 shift = pxd_bits * (u64)(4 - lv) + 3;
        u64 index = (va >> shift) & (pxd_ptrs - 1);
        u64 entry_va = pxd_va + index * 8;
        if (entry_va < page_offset_v) return 0;
        u64 desc = *(u64 *)entry_va;
        u8 kind = desc & 0x3;
        if (kind == 0x3) {
            if (lv == 3) { leaf_entry_va = entry_va; break; }
            u64 pa = desc & PTE_ADDR_MASK;
            pxd_va = __pa_to_va(pa);
        } else if (kind == 0x1) {
            leaf_entry_va = entry_va;   /* block descriptor (2MB/1GB) */
            break;
        } else {
            return 0;
        }
    }
    return (u64 *)leaf_entry_va;
}

static void flush_tlb_kernel_page(u64 va)
{
    u64 addr = (va >> 12) & ((1ULL << 44) - 1);
    asm volatile("dsb ishst" ::: "memory");
    asm volatile("tlbi vaale1is, %0" :: "r"(addr) : "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void write_kernel_u64(u64 *dst, u64 val)
{
    u64 va = (u64)dst;
    u64 *pte = walk_kernel_pte(va);
    if (!pte) { *dst = val; return; }

    u64 orig = *pte;
    *pte = (orig | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(va);
    *dst = val;
    *pte = orig;
    flush_tlb_kernel_page(va);
}

/* ---- patch_insn：写一条 32 位指令到内核 text ----
 * Tier 1: aarch64_insn_patch_text_nosync + 广播 I-cache（ic ialluis）
 * Tier 2: 走 PTE 清 PTE_RDONLY（stop_machine 同步，或 IRQ mask 兜底）
 * Tier 3: set_memory_rw → 写 → set_memory_x（vmalloc 页）
 * Tier 4: 直接写 + I-cache
 *
 * g_in_stop_machine：hook 的 stop_machine callback 调 patch_set_in_stop_machine(1)
 * 告诉本函数已在 stop_machine 内，跳过 nested stop_machine / synchronize_rcu
 *（都会死锁）。 */
struct patch_insn_data { void *addr; u32 insn; };
static int g_in_stop_machine = 0;

void patch_set_in_stop_machine(int flag) { g_in_stop_machine = flag; }

KCFI_CALLBACK(patch_insn_stop_cb, KCFI_HASH_INT_PTR, void *data)
{
    struct patch_insn_data *pd = data;
    u64 va = (u64)pd->addr;
    u64 *pte = walk_kernel_pte(va);
    if (!pte) return -1;

    u64 orig = *pte;
    *pte = (orig | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(va);
    *(u32 *)pd->addr = pd->insn;
    *pte = orig;
    flush_tlb_kernel_page(va);

    if (cached_flush_icache)
        call_flush_icache((unsigned long)pd->addr, (unsigned long)pd->addr + 4);
    return 0;
}

void patch_insn(void *addr, u32 insn)
{
    /* Tier 1 */
    if (cached_insn_patch) {
        call_insn_patch(addr, insn);
        if (cached_synchronize_rcu && !g_in_stop_machine)
            call_synchronize_rcu();
        asm volatile("ic ialluis\n\t" "dsb ish\n\t" "isb\n\t" ::: "memory");
        return;
    }

    /* Tier 2: PTE */
    pgtable_lazy_init();
    if (pgtable_ready) {
        u64 va = (u64)addr;
        u64 *pte = walk_kernel_pte(va);
        if (pte) {
            if (cached_stop_machine && !g_in_stop_machine) {
                struct patch_insn_data pd = { .addr = addr, .insn = insn };
                call_stop_machine(patch_insn_stop_cb, &pd);
            } else {
                unsigned long daif;
                u64 orig;
                asm volatile("mrs %0, daif" : "=r"(daif));
                asm volatile("msr daifset, #2" ::: "memory");

                orig = *pte;
                *pte = (orig | PTE_DBM) & ~PTE_RDONLY;
                flush_tlb_kernel_page(va);
                *(u32 *)addr = insn;
                *pte = orig;
                flush_tlb_kernel_page(va);
                if (cached_flush_icache)
                    call_flush_icache((unsigned long)addr, (unsigned long)addr + 4);

                asm volatile("msr daif, %0" :: "r"(daif) : "memory");
            }
            return;
        }
    }

    /* Tier 3: set_memory_rw → 写 → set_memory_x */
    if (cached_set_memory_rw && cached_set_memory_x) {
        unsigned long page = (unsigned long)addr & ~(PAGE_SIZE - 1);
        int rc = call_set_memory_rw(page, 1);
        if (rc == 0) {
            *(u32 *)addr = insn;
            call_set_memory_x(page, 1);
            if (cached_flush_icache)
                call_flush_icache((unsigned long)addr, (unsigned long)addr + 4);
            return;
        }
    }

    /* Tier 4: 直接写 */
    *(u32 *)addr = insn;
    if (cached_flush_icache)
        call_flush_icache((unsigned long)addr, (unsigned long)addr + 4);
}

/* ---- kmod_patch_init：解析 patch 相关内核符号 ---- */
void kmod_patch_init(void)
{
    cached_module_alloc    = kallsyms_lookup("module_alloc");
    cached_insn_patch      = kallsyms_lookup("aarch64_insn_patch_text_nosync");
    cached_flush_icache    = kallsyms_lookup("__flush_icache_range");
    if (!cached_flush_icache)
        cached_flush_icache = kallsyms_lookup("flush_icache_range");
    cached_set_memory_x    = kallsyms_lookup("set_memory_x");
    cached_set_memory_rw   = kallsyms_lookup("set_memory_rw");
    cached_stop_machine    = kallsyms_lookup("stop_machine");
    cached_synchronize_rcu = kallsyms_lookup("synchronize_rcu");
    cached_memstart_addr   = kallsyms_lookup("memstart_addr");
    cached_swapper_pg_dir  = kallsyms_lookup("swapper_pg_dir");
    cached_printk_deferred = kallsyms_lookup("printk_deferred");
}
