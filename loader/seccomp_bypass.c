/*
 * seccomp_bypass.c — 按 UID 豁免 seccomp（loader 侧）
 *
 * 为什么放 loader 而非 KPM：KPM 经自定义 syscall 448 加载，但 Android 应用
 * 进程跑在 seccomp 过滤器下，448 这种高位号几乎必被 seccomp 拦 → 应用根本
 * 调不到 448 去加载 KPM。所以"豁免 seccomp"必须在 loader 里（loader 是
 * insmod 进内核的，不走 syscall、不受 seccomp 管）。loader 装好这个 hook 后，
 * 列表里的 UID 进程才能畅通调 448。
 *
 * 做法（hook seccomp_attach_filter）：
 *   Android 应用 specialize 阶段是【子进程自己】setuid 到 app uid 后再
 *   prctl(PR_SET_SECCOMP) 装 filter，所以 seccomp_attach_filter 触发时
 *   current 已是目标进程、uid 已是 app uid。命中 UID 列表则：
 *     1. 清 thread_info.flags 的 TIF_SECCOMP 位（否则下次 syscall 进
 *        __secure_computing，mode=0 落到 default → brk #0x800 内核崩）
 *     2. 清 current->seccomp.mode = 0
 *     3. skip 掉原 attach（新 filter 不挂）
 *   一次触发即清掉【继承自 zygote 的】+【应用自己装的】全部 filter，零
 *   per-syscall 开销。
 *
 * 偏移全部【运行时扫描】内核函数得出，不写死（换 ROM/OTA 自适应）：
 *   task->seccomp : 扫 prctl_get_seccomp（return current->seccomp.mode）
 *   task->cred    : 扫 __arm64_sys_getuid（return current->cred->uid）
 *   cred->uid     : 同上，cred load 之后第一个小偏移
 * 算法移植自 SKRoot 的 find_mrs_register / find_imm_register_offset，
 * 但用手写最小 ARM64 解码器在内核内存上跑（Capstone 进不了 .ko）。
 *
 * 移植自 examples：参见 cfi_bypass.c 的 do_hook 用法。
 */
#include "kpm_internal.h"
#include "kmod_kernel.h"

/* ===== 豁免 UID 列表（从配置文件读）=====
 * 配置文件：每行一个十进制 UID，'#' 起注释，空行忽略。
 *   优先 /data/adb/kpm/seccomp_uids.conf，回退 /data/local/tmp/kpm_seccomp_uids.conf
 * 写文件的是 root / 装 loader 的人（不受 seccomp 限制），loader 读后豁免目标
 * UID，目标 app 才能调 syscall 448。 */
#define SECCOMP_CONF_PRIMARY  "/data/adb/kpm/seccomp_uids.conf"
#define SECCOMP_CONF_FALLBACK "/data/local/tmp/kpm_seccomp_uids.conf"
#define MAX_EXEMPT_UIDS 64

static unsigned int g_exempt_uids[MAX_EXEMPT_UIDS];
static int g_exempt_count = 0;

static int uid_is_exempt(unsigned int uid)
{
    for (int i = 0; i < g_exempt_count; i++)
        if (g_exempt_uids[i] == uid)
            return 1;
    return 0;
}

/* ===== 运行时偏移（扫描得出）===== */
static unsigned long off_task_seccomp = 0;   /* task_struct -> seccomp */
static unsigned long off_task_cred    = 0;   /* task_struct -> cred    */
static unsigned long off_cred_uid     = 0;   /* cred -> uid            */

#define TIF_SECCOMP 11   /* arm64 长期稳定；SKRoot 同值 */

/* 原子清 *addr 的某一位。用 ldaxr/bic/stlxr 内联汇编，避免 __atomic_*
 * 被 clang outline-atomics 编成 __aarch64_ldclr8_acq_rel（内核无此符号）。 */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static inline void atomic_clear_bit(unsigned long *addr, int bit)
{
    unsigned long mask = 1UL << bit;
    unsigned long tmp, val;
    asm volatile(
        "1: ldaxr %0, [%2]\n"
        "   bic   %0, %0, %3\n"
        "   stlxr %w1, %0, [%2]\n"
        "   cbnz  %w1, 1b\n"
        : "=&r"(val), "=&r"(tmp)
        : "r"(addr), "r"(mask)
        : "memory");
}

/* ===== 最小 ARM64 指令解码（只认我们需要的几条）===== */
/* MRS Xt, SP_EL0  ==  0xd5384100 | Rt   （SP_EL0 = op0=3,op1=0,CRn=4,CRm=1,op2=0）*/
static inline int decode_mrs_sp_el0(unsigned int insn, int *rt)
{
    if ((insn & 0xFFFFFFE0u) == 0xd5384100u) { *rt = insn & 0x1f; return 1; }
    return 0;
}

/* LDR/LDRSW (unsigned immediate), 64/32 位：
 *   LDR  Xt,[Xn,#imm]  : size=11(0x3) opc=01 -> 0xF9400000 | (imm12<<10)|(Rn<<5)|Rt, scale=8
 *   LDR  Wt,[Xn,#imm]  : size=10        -> 0xB9400000, scale=4
 *   LDRSW Xt,[Xn,#imm] :                -> 0xB9800000, scale=4
 * 返回 1 并填 rt/rn/imm（已乘 scale）。 */
static int decode_ldr_uimm(unsigned int insn, int *rt, int *rn, unsigned long *imm)
{
    unsigned int top = insn & 0xFFC00000u;
    unsigned int scale = 0;
    if (top == 0xF9400000u) scale = 8;          /* LDR Xt */
    else if (top == 0xB9400000u) scale = 4;     /* LDR Wt */
    else if (top == 0xB9800000u) scale = 4;     /* LDRSW Xt */
    else return 0;
    unsigned int imm12 = (insn >> 10) & 0xfff;
    *rn = (insn >> 5) & 0x1f;
    *rt = insn & 0x1f;
    *imm = (unsigned long)imm12 * scale;
    return 1;
}

/* ADD Xd, Xn, #imm12 (LSL 0)  ==  0x91000000 | (imm12<<10)|(Rn<<5)|Rd */
static int decode_add_imm(unsigned int insn, int *rd, int *rn, unsigned long *imm)
{
    if ((insn & 0xFFC00000u) != 0x91000000u) return 0;
    *imm = (unsigned long)((insn >> 10) & 0xfff);
    *rn  = (insn >> 5) & 0x1f;
    *rd  = insn & 0x1f;
    return 1;
}

/* 扫 [fn, fn+max) ：找 mrs sp_el0 拿到 current 寄存器 R，
 * 然后跟踪以 R 为基址的第一条 ldr/add 且偏移 > min_off 的指令，返回该偏移。
 * 用于 task->seccomp（min_off=0x200）和 task->cred（min_off=0x200）。 */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long scan_current_first_big_load(unsigned long fn, int max,
                                                  unsigned long min_off)
{
    if (!fn) return 0;
    const unsigned int *p = (const unsigned int *)fn;
    int n = max / 4;
    int cur_reg = -1;
    for (int i = 0; i < n; i++) {
        unsigned int insn = p[i];
        int rt, rn, rd; unsigned long imm;
        if (decode_mrs_sp_el0(insn, &rt)) { cur_reg = rt; continue; }
        if (cur_reg < 0) continue;
        if (decode_ldr_uimm(insn, &rt, &rn, &imm) && rn == cur_reg && imm > min_off)
            return imm;
        if (decode_add_imm(insn, &rd, &rn, &imm) && rn == cur_reg && imm > min_off)
            return imm;
        /* ret 提前结束 */
        if (insn == 0xd65f03c0u) break;
    }
    return 0;
}

/* 在 __arm64_sys_getuid 里：先定位 cred load（以 current 为基址、偏移==cred_off），
 * 之后第一条 ldr 且偏移在 [4, 0x20] 即 cred->uid（6.1 < 6.6.8 用 min=4）。
 * cred 被 load 进某寄存器 Rc，uid 再以 Rc 为基址 load。 */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long scan_cred_uid(unsigned long fn, int max, unsigned long cred_off)
{
    if (!fn) return 0;
    const unsigned int *p = (const unsigned int *)fn;
    int n = max / 4;
    int cur_reg = -1, cred_reg = -1;
    for (int i = 0; i < n; i++) {
        unsigned int insn = p[i];
        int rt, rn; unsigned long imm;
        if (decode_mrs_sp_el0(insn, &rt)) { cur_reg = rt; continue; }
        if (decode_ldr_uimm(insn, &rt, &rn, &imm)) {
            if (cred_reg < 0 && cur_reg >= 0 && rn == cur_reg && imm == cred_off) {
                cred_reg = rt;          /* cred 现在在 rt */
                continue;
            }
            if (cred_reg >= 0 && rn == cred_reg && imm >= 4 && imm <= 0x20)
                return imm;             /* cred->uid */
        }
        if (insn == 0xd65f03c0u) break;
    }
    return 0;
}

/* ===== 拿 current（loader 在内核上下文，sp_el0 = current）===== */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static inline unsigned long get_current_task(void)
{
    unsigned long t;
    asm volatile("mrs %0, sp_el0" : "=r"(t));
    return t;
}

/* ===== commit_creds hook =====
 * Android app 的 seccomp filter 是 fork 时从 zygote 继承的（copy_seccomp），
 * app 自己不调 seccomp_attach_filter —— 实测计算器启动期只有 uid=0 调过它。
 * 真正"uid 变成 app uid"的统一点是 commit_creds（specialize 的 setresuid →
 * commit_creds(new)）。此时 new->uid 已是目标 uid，且 seccomp 已继承好，正好清。
 *
 * 清 seccomp（去掉继承来的过滤器）：
 *   - 清 thread_info.flags 的 TIF_SECCOMP 位（否则 mode=0 进 __secure_computing
 *     落 default → brk 崩）
 *   - 清 current->seccomp.mode = 0
 * commit_creds(struct cred *new)：x0=new cred，new->uid 在 cred+off_cred_uid。 */
static int (*backup_commit_creds)(void *new_cred) = 0;
static unsigned long cached_commit_creds = 0;

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int replace_commit_creds(void *new_cred)
{
    unsigned int uid = (unsigned int)-1;
    if (new_cred && off_cred_uid)
        uid = *(unsigned int *)((char *)new_cred + off_cred_uid);

    /* 先让原 commit_creds 完成赋值（current->cred = new）*/
    int ret = 0;
    if (backup_commit_creds)
        ret = backup_commit_creds(new_cred);

    if (uid != (unsigned int)-1 && uid_is_exempt(uid)) {
        unsigned long task = get_current_task();
        if (task) {
            unsigned long *flags_p = (unsigned long *)task;
            int was_set = (*flags_p >> TIF_SECCOMP) & 1;
            atomic_clear_bit(flags_p, TIF_SECCOMP);
            if (off_task_seccomp) {
                /* struct seccomp: mode@+0, filter_count@+4, filter@+8。
                 * 清 mode=0 + filter_count=0，避免 /proc/pid/status 出现
                 * "Seccomp:0 但 Seccomp_filters:1" 的矛盾态（反作弊检测点）。
                 * filter 指针保留，让进程退出时内核正常释放过滤器链。 */
                *(unsigned int *)(task + off_task_seccomp)     = 0;  /* mode */
                *(unsigned int *)(task + off_task_seccomp + 4) = 0;  /* filter_count */
            }
            /* 只在真清掉了（之前 TIF_SECCOMP 还在）时打一次，避免刷屏 */
            if (was_set)
                klog("kpm_loader: seccomp exempt uid=%u (cleared)\n", uid);
        }
    }
    return ret;
}

/* ===== 配置文件读取与解析 ===== */
/* 解析文本：逐行取十进制 UID，'#' 注释、空白忽略。填进 g_exempt_uids。 */
static void parse_uid_text(const char *buf, long len)
{
    long i = 0;
    while (i < len && g_exempt_count < MAX_EXEMPT_UIDS) {
        /* 跳过行首空白 */
        while (i < len && (buf[i] == ' ' || buf[i] == '\t' ||
                           buf[i] == '\r' || buf[i] == '\n'))
            i++;
        if (i >= len) break;
        if (buf[i] == '#') {                 /* 注释行：跳到行尾 */
            while (i < len && buf[i] != '\n') i++;
            continue;
        }
        if (buf[i] < '0' || buf[i] > '9') {  /* 非数字开头：跳到行尾 */
            while (i < len && buf[i] != '\n') i++;
            continue;
        }
        unsigned int v = 0;
        while (i < len && buf[i] >= '0' && buf[i] <= '9') {
            v = v * 10 + (unsigned int)(buf[i] - '0');
            i++;
        }
        g_exempt_uids[g_exempt_count++] = v;
        while (i < len && buf[i] != '\n') i++;   /* 行尾剩余 */
    }
}

/* 读一个配置文件，成功（读到 >=1 个 uid）返回 1。复用 kmod_read_whole_file。 */
static int load_uid_conf(const char *path)
{
    long sz = 0;
    char *data = kmod_read_whole_file(path, &sz, 0x10000);  /* 配置 <=64K */
    if (!data || sz <= 0) return 0;

    g_exempt_count = 0;
    parse_uid_text(data, sz);
    vfree(data);

    klog("kpm_loader: seccomp conf %s -> %d uid(s)\n", path, g_exempt_count);
    return g_exempt_count > 0;
}

static void load_exempt_uids(void)
{
    g_exempt_count = 0;
    if (load_uid_conf(SECCOMP_CONF_PRIMARY)) return;
    load_uid_conf(SECCOMP_CONF_FALLBACK);
}

/* ===== init / exit ===== */
void seccomp_bypass_init(void)
{
    unsigned long prctl_get = kallsyms_lookup("prctl_get_seccomp");
    unsigned long sys_getuid = kallsyms_lookup("__arm64_sys_getuid");

    if (prctl_get)
        off_task_seccomp = scan_current_first_big_load(prctl_get, 0x40, 0x200);
    if (sys_getuid) {
        off_task_cred = scan_current_first_big_load(sys_getuid, 0x60, 0x200);
        if (off_task_cred)
            off_cred_uid = scan_cred_uid(sys_getuid, 0x60, off_task_cred);
    }

    klog("kpm_loader: seccomp offsets task->seccomp=%lx cred=%lx uid=%lx\n",
         off_task_seccomp, off_task_cred, off_cred_uid);

    if (!off_task_seccomp || !off_task_cred || !off_cred_uid) {
        klog("kpm_loader: seccomp_bypass disabled (offset scan failed)\n");
        return;
    }

    /* 读配置文件拿豁免 UID 列表；为空则装 hook 但不豁免任何人（可后续
     * 写配置 + 重载/重新 insmod 生效）。 */
    load_exempt_uids();
    if (g_exempt_count == 0)
        klog("kpm_loader: seccomp exempt list empty (no %s / %s)\n",
             SECCOMP_CONF_PRIMARY, SECCOMP_CONF_FALLBACK);

    cached_commit_creds = kallsyms_lookup("commit_creds");
    if (!cached_commit_creds) {
        klog("kpm_loader: commit_creds not found, seccomp bypass disabled\n");
        return;
    }
    long err = do_hook((void *)cached_commit_creds,
                       (void *)replace_commit_creds,
                       (void **)&backup_commit_creds);
    if (err)
        klog("kpm_loader: hook commit_creds failed: %ld\n", err);
    else
        klog("kpm_loader: hooked commit_creds at %lx (seccomp uid-exempt)\n",
             cached_commit_creds);
}

void seccomp_bypass_exit(void)
{
    if (backup_commit_creds) {
        do_unhook((void *)cached_commit_creds);
        backup_commit_creds = 0;
    }
}
