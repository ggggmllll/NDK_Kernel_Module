#ifndef KMOD_KERNEL_H
#define KMOD_KERNEL_H

#include "kmod_types.h"
#include "kmod_string.h"

/*
 * kmod_kernel.h — 内核 API 声明 + kallsyms 基础设施
 *
 * 实现在 src/kmod_kernel.c（库编译一次，多 .c 模块共享）。
 * kallsyms_lookup_name 在 GKI 5.10+ 不导出；模块 init 早期调一次
 * kallsyms_init()（三策略：fixup_ko 标记 / kprobe / sprintf 扫描），
 * 之后 klog 与 kallsyms_lookup 可用。
 */

/* =========================================================================
 * printk
 *
 * kallsyms_init() 解析（5.x printk / 6.x _printk）。解析前为 0 —— 调用前
 * 确保已 kallsyms_init()。不直接引用符号，避免 5.10 上的 GOT 重定位。
 * ========================================================================= */
extern void (*klog)(const char *fmt, ...);

/* 加锁场景下的日志：走 printk_deferred（irq_work 延迟输出，不抢 logbuf_lock，
 * 不会在已持有 logbuf_lock 的上下文里重入死锁）。只接受纯字符串，无格式化参数。*/
void klog_deferred(const char *fmt);

/* =========================================================================
 * kallsyms 基础设施
 * ========================================================================= */
void kallsyms_init(void);
void resolve_printk(void);
unsigned long kallsyms_lookup(const char *name);

/* =========================================================================
 * __cfi_slowpath stub
 *
 * -fsanitize=cfi 为每个间接调用生成对此符号的引用。5.x shadow-CFI 导出，
 * 6.x kCFI 不导出；定义自己的 stub 让模块在两代内核都能加载。
 * 实现在 kmod_kernel.c（全局唯一定义）。
 * ========================================================================= */
void __cfi_slowpath(u64 id, void *ptr, void *diag);

/* =========================================================================
 * 内存分配
 * ========================================================================= */
extern void *vmalloc(unsigned long size) __attribute__((weak));
extern void vfree(const void *addr) __attribute__((weak));
extern void *kvmalloc(unsigned long size) __attribute__((weak));
extern void *kmalloc(unsigned long size, unsigned int flags) __attribute__((weak));
extern void kfree(const void *addr) __attribute__((weak));

/* =========================================================================
 * 同步：mutex（不透明，只把地址传给内核）
 *
 * ARM64 GKI 5.10 的 struct mutex 32–64 字节，CONFIG_LOCKDEP 下更大。
 * 128 字节是 4.4–6.12 的安全上界；偏小会让 __mutex_init/mutex_lock
 * 越界写到相邻 BSS。
 * ========================================================================= */
struct mutex {
    char __opaque[128];
};
struct lock_class_key {
    char __opaque[64];   /* CONFIG_LOCKDEP 下含 subkeys[8] */
};
extern void __mutex_init(struct mutex *m, const char *name, struct lock_class_key *key) __attribute__((weak));
extern void mutex_lock(struct mutex *m) __attribute__((weak));
extern void mutex_unlock(struct mutex *m) __attribute__((weak));

/* =========================================================================
 * kprobe —— kallsyms_init 的后备策略用
 *
 * ARM64 5.10 的 struct kprobe：addr 在偏移 40（hlist 16 + list 16 + nmissed 8）。
 * 320 字节是 4.4–6.12 的安全上界。
 * ========================================================================= */
struct kprobe {
    char __pad0[40];
    void *addr;                  /* offset 40 */
    const char *symbol_name;     /* offset 48 */
    char __opaque[272];
};
extern int register_kprobe(struct kprobe *p) __attribute__((weak));
extern void unregister_kprobe(struct kprobe *p) __attribute__((weak));

/* =========================================================================
 * 文件 I/O（最小结构，匹配 Linux 5.10 arm64 布局）
 * ========================================================================= */
struct file;
struct iov_iter;

/* kiocb —— 只依赖 ki_filp@0x00 和 ki_pos@0x08 */
struct kiocb {
    struct file *ki_filp;
    long long ki_pos;
};

struct file_operations {
    void *owner;                                            /* 0x00 */
    long long (*llseek)(struct file *, long long, int);     /* 0x08 */
    long (*read)(struct file *, char *, size_t, long long *);        /* 0x10 */
    long (*write)(struct file *, const char *, size_t, long long *);/* 0x18 */
    long (*read_iter)(struct kiocb *, struct iov_iter *);   /* 0x20 */
    long (*write_iter)(struct kiocb *, struct iov_iter *);  /* 0x28 */
};

struct file {
    unsigned long f_u[2];                     /* 0x00 — union, 16 bytes */
    void *f_path_mnt, *f_path_dentry;         /* 0x10 — struct path */
    void *f_inode;                            /* 0x20 */
    const struct file_operations *f_op;       /* 0x28 */
};

struct kvec {
    void *iov_base;
    unsigned long iov_len;
};

extern int filp_close(struct file *filp, void *id) __attribute__((weak));
extern long long vfs_llseek(struct file *filp, long long offset, int origin) __attribute__((weak));
extern long seq_read(struct file *, char *, size_t, long long *) __attribute__((weak));
extern void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
                          const struct kvec *kvec, unsigned long nr_segs,
                          unsigned long count) __attribute__((weak));

/* 内核态读文件：优先 read_iter（支持 kernel buffer，ITER_KVEC），否则退到
 * f_op->read（/proc 类文件）。*pos 为文件偏移，返回读取字节数。*/
long kmod_read_file(struct file *filp, void *buf, unsigned long len, long long *pos);

/* 读整个文件到 vmalloc 缓冲（filp_open 懒解析）。成功返回数据指针(末尾补 \0)
 * 并经 *out_size 回传长度，用完 vfree；失败返回 NULL。max_size=0 用默认 16MB。 */
void *kmod_read_whole_file(const char *path, long *out_size, unsigned long max_size);

/* =========================================================================
 * patch 基础设施（call_* + pgtable）
 *
 * 修改内核代码/数据的能力：call_* 包装内核的 patch/内存 API（由
 * kmod_patch_init 解析），pgtable 子系统能改 __ro_after_init 内存
 *（sys_call_table 等，set_memory_rw 够不着的）。kmod_hook 依赖这层。
 *
 * kmod_patch_init() 在 kallsyms_init() 之后调一次。
 * ========================================================================= */
void kmod_patch_init(void);

void *call_module_alloc(unsigned long size);
void  call_flush_icache(unsigned long start, unsigned long end);
int   call_set_memory_x(unsigned long addr, int numpages);
int   call_set_memory_rw(unsigned long addr, int numpages);
int   call_insn_patch(void *addr, u32 insn);
int   call_stop_machine(int (*fn)(void *), void *data);
void  call_synchronize_rcu(void);

/* 直接写 __ro_after_init / rodata 的 64 位内存（临时清 PTE_RDONLY）。 */
void write_kernel_u64(u64 *dst, u64 val);

/* 写一条 32 位指令到内核 text（多 tier fallback + I-cache 维护 + stop_machine
 * 同步）。kmod_hook 的 hook_install/uninstall 用它改函数入口。
 *
 * patch_set_in_stop_machine：hook 的 stop_machine callback 进入时设 1、退出
 * 设 0，让 patch_insn 跳过 nested stop_machine / synchronize_rcu（会死锁）。 */
void patch_insn(void *addr, u32 insn);
void patch_set_in_stop_machine(int flag);

#endif /* KMOD_KERNEL_H */
