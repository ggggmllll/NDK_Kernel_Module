/*
 * loader.c — KPM Loader kernel module
 *
 * A standalone kernel module that loads Kernel Patch Modules (KPM),
 * provides ARM64 inline hook capability, and resolves kernel symbols
 * by parsing /proc/kallsyms.
 *
 * KPM format: ET_REL ELF with custom sections
 *   .kpm.info   — "key=value\0" metadata (name, version, license, ...)
 *   .kpm.init   — 8-byte function pointer to init
 *   .kpm.ctl0   — 8-byte function pointer to ctl0
 *   .kpm.ctl1   — 8-byte function pointer to ctl1
 *   .kpm.exit   — 8-byte function pointer to exit
 *
 * Build: NDK clang -c → .o → ld -r -T linker.lds → merged.o → KPatcher → .ko
 * Usage: insmod loader.ko kpm_path="/path/to/module.kpm"
 *        echo "load /path/to/module.kpm" > /proc/kpm_loader
 */

/* =========================================================================
 * Section 1: Self-contained type definitions (no kernel headers required)
 * ========================================================================= */

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

typedef u64 phys_addr_t;
typedef u64 dma_addr_t;
typedef unsigned long uintptr_t;

/* Kernel-typical typedefs */
typedef long ssize_t;
typedef unsigned long size_t;
typedef long long loff_t;
typedef unsigned short umode_t;
#define __user
#define __init
#define __exit

#define KERNEL_SPACE_BASE 0xffffffc000000000UL
#define NULL ((void *)0)
#define true 1
#define false 0
typedef u8 bool;

/* GKI namespace import — generates the modinfo entry the kernel needs */
#define MODULE_IMPORT_NS(ns) \
    static const char __UNIQUE_ID_import_ns[] \
    __attribute__((section(".modinfo"), used, aligned(1))) = "import_ns=" #ns

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

#define offsetof(type, member) ((unsigned long)(&((type *)0)->member))
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* ELF64 types */
typedef u64 Elf64_Addr;
typedef u64 Elf64_Off;
typedef u16 Elf64_Half;
typedef u32 Elf64_Word;
typedef s32 Elf64_Sword;
typedef u64 Elf64_Xword;
typedef s64 Elf64_Sxword;

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word    sh_name;
    Elf64_Word    sh_type;
    Elf64_Xword   sh_flags;
    Elf64_Addr    sh_addr;
    Elf64_Off     sh_offset;
    Elf64_Xword   sh_size;
    Elf64_Word    sh_link;
    Elf64_Word    sh_info;
    Elf64_Xword   sh_addralign;
    Elf64_Xword   sh_entsize;
} Elf64_Shdr;

typedef struct {
    Elf64_Word    st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half    st_shndx;
    Elf64_Addr    st_value;
    Elf64_Xword   st_size;
} Elf64_Sym;

typedef struct {
    Elf64_Addr    r_offset;
    Elf64_Xword   r_info;
    Elf64_Sxword  r_addend;
} Elf64_Rela;

#define ELFMAG0     0x7f
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define SELFMAG     4
#define ELFMAG      "\177ELF"

#define ET_REL      1
#define EM_AARCH64  183

#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_RELA     4
#define SHT_NOBITS   8
#define SHT_REL      9

#define SHF_WRITE      (1 << 0)
#define SHF_ALLOC      (1 << 1)
#define SHF_EXECINSTR  (1 << 2)

#define SHN_UNDEF   0
#define SHN_ABS     0xfff1

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define ELF64_ST_TYPE(info) ((info) & 0xF)

#define ELF64_R_SYM(info)     ((u32)((info) >> 32))
#define ELF64_R_TYPE(info)    ((u32)(info))

/* AArch64 relocation types */
#define R_AARCH64_NONE                  0
#define R_AARCH64_ABS64                 0x101
#define R_AARCH64_ABS32                 0x102
#define R_AARCH64_ABS16                 0x103
#define R_AARCH64_PREL64                0x104
#define R_AARCH64_PREL32                0x105
#define R_AARCH64_PREL16                0x106
#define R_AARCH64_MOVW_UABS_G0          0x107
#define R_AARCH64_MOVW_UABS_G0_NC       0x108
#define R_AARCH64_MOVW_UABS_G1          0x109
#define R_AARCH64_MOVW_UABS_G1_NC       0x10a
#define R_AARCH64_MOVW_UABS_G2          0x10b
#define R_AARCH64_MOVW_UABS_G2_NC       0x10c
#define R_AARCH64_MOVW_UABS_G3          0x10d
#define R_AARCH64_MOVW_SABS_G0          0x10e
#define R_AARCH64_MOVW_SABS_G1          0x10f
#define R_AARCH64_MOVW_SABS_G2          0x110
#define R_AARCH64_MOVW_PREL_G0          0x111
#define R_AARCH64_MOVW_PREL_G0_NC       0x112
#define R_AARCH64_ADR_PREL_PG_HI21      0x113
#define R_AARCH64_ADR_PREL_PG_HI21_NC   0x114
#define R_AARCH64_ADD_ABS_LO12_NC       0x115
#define R_AARCH64_LDST8_ABS_LO12_NC     0x116
#define R_AARCH64_TSTBR14               0x117
#define R_AARCH64_CONDBR19              0x118
#define R_AARCH64_JUMP26                0x11a
#define R_AARCH64_CALL26                0x11b
#define R_AARCH64_LDST16_ABS_LO12_NC    0x11c
#define R_AARCH64_LDST32_ABS_LO12_NC    0x11d
#define R_AARCH64_LDST64_ABS_LO12_NC    0x11e
#define R_AARCH64_LDST128_ABS_LO12_NC   0x11f

/* List structure */
struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
#define list_for_each_entry(pos, head, member) \
    for (pos = list_first_entry(head, typeof(*pos), member); \
         &pos->member != (head); \
         pos = list_entry(pos->member.next, typeof(*pos), member))

/* KPM module structure */
typedef long (*kpm_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_ctl0call_t)(const char *ctl_args, char *out_msg, int outlen);
typedef long (*kpm_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*kpm_exitcall_t)(void *reserved);

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
    unsigned int text_size; /* PAGE_ALIGN'd size of executable region */
    unsigned int text_used; /* actual bytes used by text sections (pre-align) */
    void *got_base;     /* GOT slot array (vmalloc'd, freed on unload) */
    struct list_head list;
};

/* Loader API table — passed to KPM init via reserved parameter */
struct kpm_api {
    void *(*lookup_symbol)(const char *name);
    long (*load_kpm)(const char *path, const char *args);
    long (*unload_kpm)(const char *name);
    long (*hook)(void *func, void *replace, void **backup);
    void (*unhook)(void *func);
    void (*printk)(const char *fmt, ...);
};

/* =========================================================================
 * Section 2: Minimal libc implementations
 * ========================================================================= */

static int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *(unsigned char *)a - *(unsigned char *)b;
}

static int strncmp(const char *a, const char *b, unsigned long n)
{
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? *(unsigned char *)a - *(unsigned char *)b : 0;
}

static unsigned long strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return p - s;
}

static char *strcpy(char *dst, const char *src)
{
    char *d = dst;
    while ((*d++ = *src++));
    return dst;
}

static char *strncpy(char *dst, const char *src, unsigned long n)
{
    char *d = dst;
    while (n && (*d++ = *src++)) n--;
    while (n--) *d++ = 0;
    return dst;
}

__attribute__((used))
static char *strncat(char *dst, const char *src, unsigned long n)
{
    char *d = dst;
    while (*d) d++;
    while (n-- && (*d++ = *src++));
    if (n == (unsigned long)-1) *d = 0;
    return dst;
}

static void *memcpy(void *dst, const void *src, unsigned long n)
{
    char *d = dst;
    const char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

static void *memmove(void *dst, const void *src, unsigned long n)
{
    if (dst < src) return memcpy(dst, src, n);
    char *d = (char *)dst + n;
    const char *s = (const char *)src + n;
    while (n--) *--d = *--s;
    return dst;
}

static void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static int memcmp(const void *a, const void *b, unsigned long n)
{
    const unsigned char *pa = a, *pb = b;
    while (n-- && *pa == *pb) { pa++; pb++; }
    return n != (unsigned long)-1 ? *pa - *pb : 0;
}

/* Simple formatting helpers — avoid varargs portability issues */
static int buf_append(char *buf, int size, int pos, const char *s)
{
    while (pos < size - 1 && *s) buf[pos++] = *s++;
    return pos;
}

static int buf_append_dec(char *buf, int size, int pos, int val)
{
    char tmp[12];
    int i = 0;
    if (val < 0) { buf[pos++] = '-'; val = -val; }
    if (val == 0) tmp[i++] = '0';
    else while (val && i < 11) { tmp[i++] = '0' + (val % 10); val /= 10; }
    while (i > 0 && pos < size - 1) buf[pos++] = tmp[--i];
    return pos;
}

/* =========================================================================
 * Section 3: Kernel API declarations (resolved at module load time)
 * ========================================================================= */

/* printk resolved at runtime via kallsyms_lookup_name — see resolve_printk().
 * No direct symbol reference avoids GOT relocations (type 311) on 5.10. */
static void (*klog)(const char *fmt, ...) = 0;

/* Self-contained __cfi_slowpath stub — eliminates external UNDEF dependency.
 * -fsanitize=cfi generates calls to __cfi_slowpath for every indirect call.
 * 5.x shadow-CFI exports this symbol, but 6.x kCFI does NOT.
 * Defining our own stub makes the module load on both without an external ref.
 * Marked no_sanitize to prevent recursive CFI instrumentation. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
void __cfi_slowpath(u64 id, void *ptr, void *diag)
{
    (void)id; (void)ptr; (void)diag;
    /* The loader hooks the kernel's __cfi_slowpath at init for KPM bypass.
     * Module-internal indirect calls pass through here — the loader is a
     * trusted component that intentionally operates outside CFI enforcement. */
}

/* vmalloc / vfree */
extern void *vmalloc(unsigned long size);
extern void vfree(const void *addr);
extern void *kvmalloc(unsigned long size);

/* kmalloc / kfree */
extern void *kmalloc(unsigned long size, unsigned int flags);
extern void kfree(const void *addr);

/* File I/O — minimal struct definitions matching Linux 5.10 arm64 layout */
struct file;
struct file_operations {
    void *owner;                                            /* 0x00 */
    long long (*llseek)(struct file *, long long, int);    /* 0x08 */
    ssize_t (*read)(struct file *, char *, size_t,         /* 0x10 */
                    long long *);
    ssize_t (*write)(struct file *, const char *, size_t,  /* 0x18 */
                     long long *);
    ssize_t (*read_iter)(struct kiocb *, struct iov_iter *); /* 0x20 */
    ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);/* 0x28 */
};
struct file {
    unsigned long f_u[2];                     /* 0x00 — union, 16 bytes (rcu_head) */
    void *f_path_mnt, *f_path_dentry;         /* 0x10 — struct path */
    void *f_inode;                            /* 0x20 */
    const struct file_operations *f_op;       /* 0x28 */
};
struct inode;

/* kiocb — we only depend on ki_filp@0x00 and ki_pos@0x08 */
struct kiocb {
    struct file *ki_filp;
    long long ki_pos;
};
struct iov_iter;

/* kvec for kernel-space I/O */
struct kvec {
    void *iov_base;
    unsigned long iov_len;
};

/* filp_open is not exported on GKI 6.1 — resolved via kallsyms_lookup_name */
extern int filp_close(struct file *filp, void *id);
extern long long vfs_llseek(struct file *filp, long long offset, int origin);

/* seq_read — exported on GKI; used directly for /proc files */
extern ssize_t seq_read(struct file *, char *, size_t, long long *);

/* iov_iter_kvec — exported on GKI; used to build a kernel-buffer iterator */
extern void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
                          const struct kvec *kvec, unsigned long nr_segs,
                          unsigned long count);

/* GKI doesn't export kernel_read.  Use read_iter (for regular files) or
 * seq_read (for /proc files) directly.
 *
 * __attribute__((no_sanitize("cfi"), no_sanitize("kcfi"))) is critical: function pointers from
 * file_operations live in the kernel, so CFI_ICALL validation would fail. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static ssize_t kpm_kernel_read(struct file *filp, void *buf,
                                unsigned long len, long long *pos)
{
    if (!filp || !filp->f_op)
        return 0;

    /* Prefer read_iter (works with kernel buffers via ITER_KVEC) */
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
        ssize_t ret = filp->f_op->read_iter(k, iter);
        if (ret > 0)
            *pos = k->ki_pos;
        return ret;
    }

    /* Fallback: seq_read for /proc files (exported, but uses copy_to_user
     * internally — may fail on kernels with strict PAN/user access checks) */
    if (filp->f_op->read)
        return filp->f_op->read(filp, buf, len, pos);

    return 0;
}

/* Kprobe — used to resolve kallsyms_lookup_name at runtime without
 * needing fixup_ko or /proc/kallsyms.  We define the struct ourselves
 * so the module compiles with NDK (no kernel headers).
 *
 * The kernel's struct kprobe on ARM64 5.10 has addr at offset 40 (after
 * hlist 16, list 16, nmissed 8).  We MUST match these offsets because the
 * kernel reads/writes fields at kernel-defined offsets.  320 bytes total
 * is a safe over-estimate for 4.4–6.12. */
struct kprobe {
    char __pad0[40];             /* hlist_node (16) + list_head (16) + nmissed (8) */
    void *addr;                  /* offset 40 */
    const char *symbol_name;     /* offset 48 */
    char __opaque[272];          /* remaining fields + safety margin */
};
extern int register_kprobe(struct kprobe *p);
extern void unregister_kprobe(struct kprobe *p);

/* Mutex — opaque to the module; we only pass its address to the kernel.
 * The kernel's struct mutex on ARM64 GKI 5.10 is 32-64 bytes (owner 8,
 * wait_lock 4, osq 4, wait_list 16, plus optional debug fields magic
 * 8, owner_cpu 8, owner_sp 8, dep_map ~24).  With CONFIG_LOCKDEP it
 * can exceed 80 bytes.  If we under-size it, __mutex_init and mutex_lock
 * write past our allocation into adjacent BSS variables.
 * 128 bytes is a safe over-estimate for any 4.4–6.12 kernel. */
struct mutex {
    char __opaque[128];
};
struct lock_class_key {
    /* With CONFIG_LOCKDEP this contains subkeys[8] (64 bytes).
     * Without LOCKDEP it's empty.  64 bytes is safe for all configs. */
    char __opaque[64];
};
extern void __mutex_init(struct mutex *m, const char *name, struct lock_class_key *key);
extern void mutex_lock(struct mutex *m);
extern void mutex_unlock(struct mutex *m);

/* Kernel symbols for flags */
#define GFP_KERNEL 0xcc0   /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */
#define O_RDONLY    0
#define O_WRONLY    1

/* Min, max, align */
#define PAGE_SIZE  4096
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

/* Bit operations */
#define BIT(n) (1ULL << (n))

/* =========================================================================
 * Section 5: Kernel symbol lookup
 *
 * kallsyms_lookup_name is NOT exported on GKI 5.10+.  ARM64 5.10+ removed
 * set_fs(), so kernel-space file reads of /proc/kallsyms fail with -EFAULT
 * (seq_read → copy_to_user rejects kernel buffers).
 *
 * Solution: fixup_ko reads /proc/kallsyms from userspace at patch time and
 * writes the address into the magic marker below.  At init, the loader
 * picks it up and resolves all other symbols.
 *
 * Fallback: echo "kaddr <hex>" > /proc/kpm_loader at runtime.
 * ========================================================================= */

/* volatile: prevent LTO from eliding the pointer deref or caching
 * the NULL initializer across the fixup_ko patch applied at runtime */
static unsigned long (*volatile kallsyms_lookup_name_fn)(const char *name) = 0;

/* Magic marker — fixup_ko locates this string and patches the 8 bytes
 * immediately after it with the real kallsyms_lookup_name address.
 * volatile + used prevents LTO/CFI from optimizing the struct away. */
static struct {
    char marker[32];  /* exactly 32 bytes, addr at 8-byte-aligned offset 32 */
    volatile unsigned long addr;
} kallsyms_patch __attribute__((aligned(8), used)) = {
    "KPM_KALLSYMS_NAME_PATCH_SLOT_V1X",
    0
};

/* All symbols the loader needs, resolved via kallsyms_lookup_name.
 * NULL terminates the list. */
static const char *const needed_syms[] = {
    "module_alloc",
    "aarch64_insn_patch_text_nosync",
    "__flush_icache_range",
    "flush_icache_range",
    "set_memory_x",
    "set_memory_rw",
    "printk_deferred",
    "_copy_to_user",
    "raw_copy_to_user",
    "copy_to_user",
    "__arch_copy_to_user",
    "__copy_to_user",
    "__uaccess_ttbr0_enable",
    "__uaccess_ttbr0_disable",
    "strncpy_from_user",
    "filp_open",
    "printk",
    "__cfi_slowpath_diag",
    "__cfi_slowpath",
    "report_cfi_failure",
    "swapper_pg_dir",
    "memstart_addr",
    "stop_machine",
    "synchronize_rcu",
    NULL
};

/* KPM memory area tracking — used by bypass_kcfi to decide whether
 * to skip CFI checks for code in KPM regions. */
#define KPM_AREA_MAX 16
static struct {
    unsigned long start;
    unsigned long end;
} kpm_areas[KPM_AREA_MAX];
static int kpm_area_count = 0;

static void kpm_area_add(unsigned long start, unsigned long size)
{
    if (kpm_area_count < KPM_AREA_MAX) {
        kpm_areas[kpm_area_count].start = start;
        kpm_areas[kpm_area_count].end = start + size;
        kpm_area_count++;
    }
}

static void kpm_area_remove(unsigned long start)
{
    for (int i = 0; i < kpm_area_count; i++) {
        if (kpm_areas[i].start == start) {
            kpm_areas[i] = kpm_areas[--kpm_area_count];
            return;
        }
    }
}

static unsigned long cached_module_alloc = 0;
static unsigned long cached_insn_patch = 0;
static unsigned long cached_flush_icache = 0;
static unsigned long cached_set_memory_x = 0;
static unsigned long cached_set_memory_rw = 0;
static unsigned long cached_stop_machine = 0;
static unsigned long cached_synchronize_rcu = 0;
static unsigned long cached_printk_deferred = 0;
static unsigned long cached_cfi_slowpath = 0;
static unsigned long cached_report_cfi_failure = 0;

static bool is_kpm_area(unsigned long addr)
{
    for (int i = 0; i < kpm_area_count; i++) {
        if (addr >= kpm_areas[i].start && addr < kpm_areas[i].end)
            return true;
    }
    return false;
}
static unsigned long cached_arch_copy_to_user = 0;
static unsigned long cached_copy_to_user = 0;
static unsigned long cached_raw_copy_to_user = 0;
static unsigned long cached_legacy_copy_to_user = 0;
static unsigned long cached_ttbr0_enable = 0;
static unsigned long cached_ttbr0_disable = 0;
static unsigned long cached_strncpy_from_user = 0;
static unsigned long cached_swapper_pg_dir = 0;
static unsigned long cached_memstart_addr = 0;
static unsigned long cached_filp_open = 0;

/* ---- KernelPatch KPM compatibility symbols ----
 * KernelPatch KPMs reference these symbols; they must be available for
 * KPM symbol resolution.  Placed in .data (not .bss) so their addresses
 * are file-backed and resolvable via the local symbol table. */
#define KP_VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

static u32 kver __attribute__((used, section(".data"))) = 0;
static u32 kpver __attribute__((used, section(".data"))) = KP_VERSION(0, 13, 0);

/* KernelPatch asm/current.h compat: values for Android GKI 5.10.
 * Placed in .data so they are file-backed for local_syms addressing. */
static int kp_sp_el0_is_current          __attribute__((used, section(".data"))) = 1;
static int kp_thread_info_in_task        __attribute__((used, section(".data"))) = 1;
static int kp_sp_el0_is_thread_info      __attribute__((used, section(".data"))) = 0;
static int kp_thread_size                __attribute__((used, section(".data"))) = 16384;
static int kp_task_in_thread_info_offset __attribute__((used, section(".data"))) = 0;
static int kp_has_syscall_wrapper        __attribute__((used, section(".data"))) = 0;
/* Function pointer variable for printk — KPMs declare printk as
 * extern void (*printk)(const char *fmt, ...) and dereference it. */
static void (*kp_printk_ptr)(const char *fmt, ...) __attribute__((used, section(".data")));
static unsigned long (*kp_kallsyms_lookup_name_ptr)(const char *name) __attribute__((used, section(".data")));

/* Inline copy_to_user using STTRB (ARMv8.0 unprivileged store).
 * Used as last-resort fallback when the kernel's __arch_copy_to_user
 * is unavailable or broken (e.g., hangs on 6.1+Gunyah).
 *
 * Cortex-A57 (ARMv8.0) has STTRB but not PAN, so no `msr pan` needed.
 * Uses old-format __ex_table (8 bytes: insn+fixup) compatible with 5.10.
 * On 5.16+ the kernel may need EX_TYPE_UACCESS_ERR_ZERO to zero registers,
 * but without it the remaining count in rem still yields correct behavior.
 *
 * Returns bytes NOT copied (0 = success). */
__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long kp_inline_copy_to_user(void *to, const void *from, unsigned long n)
{
    unsigned long to_a  = (unsigned long)to;
    unsigned long frm_a = (unsigned long)from;
    unsigned long rem   = n;

    __asm__ volatile(
        "1:  cbz %2, 2f\n"
        "    ldrb w9, [%1], #1\n"
        "kp_sttr_insn_site:\n"
        "    sttrb w9, [%0]\n"
        "    add %0, %0, #1\n"
        "    sub %2, %2, #1\n"
        "    b 1b\n"
        "2:\n"
        "kp_sttr_fixup:\n"
        ".pushsection __ex_table, \"a\"\n"
        "    .align 2\n"
        "    .long (kp_sttr_insn_site - .)\n"
        "    .long (kp_sttr_fixup - .)\n"
        ".popsection\n"
        : "+r" (to_a), "+r" (frm_a), "+r" (rem)
        :
        : "memory", "x9"
    );
    return rem;
}

/* Simple copy_to_user wrapper for KPM compatibility.
 * Tries kallsyms-resolved kernel functions first, then falls back
 * to inline STTR.  On arm64 SW PAN systems we enable uaccess before
 * any user copy and disable it afterwards. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int compat_copy_to_user(void *to, const void *from, int n)
{
    typedef unsigned long (*fn_t)(void *to, const void *from, unsigned long n);
    typedef void (*uaccess_fn_t)(void);
    unsigned long rc = (unsigned long)n;
    const char *used = "none";

    /* Kernel addresses: use direct memcpy (not subject to PAN/SW PAN) */
    if ((unsigned long)to >= KERNEL_SPACE_BASE) {
        __builtin_memcpy(to, from, (unsigned long)n);
        return n;
    }

    if (cached_ttbr0_enable)
        ((uaccess_fn_t)cached_ttbr0_enable)();

    if (cached_copy_to_user) {
        used = "_copy_to_user";
        rc = ((fn_t)cached_copy_to_user)(to, from, (unsigned long)n);
    } else if (cached_arch_copy_to_user) {
        used = "__arch_copy_to_user";
        rc = ((fn_t)cached_arch_copy_to_user)(to, from, (unsigned long)n);
    } else if (cached_raw_copy_to_user) {
        used = "raw_copy_to_user";
        rc = ((fn_t)cached_raw_copy_to_user)(to, from, (unsigned long)n);
    } else if (cached_legacy_copy_to_user) {
        used = "__copy_to_user";
        rc = ((fn_t)cached_legacy_copy_to_user)(to, from, (unsigned long)n);
    } else {
        used = "inline_sttr";
        rc = kp_inline_copy_to_user(to, from, (unsigned long)n);
    }

    klog("kpm_loader: compat_copy_to_user via %s to=%px n=%d rc=%lu\n",
         used, to, n, rc);

    if (cached_ttbr0_disable)
        ((uaccess_fn_t)cached_ttbr0_disable)();

    return rc ? (int)(n - (int)rc) : n;
}

/* Local symbol table: symbols provided by the loader itself (not from kernel).
 * When a KPM references kpver/kver/compat_copy_to_user as undefined symbols,
 * they are resolved here instead of via kallsyms_lookup_name.
 *
 * String functions are included so KernelPatch KPMs that use kfunc_def() wrappers
 * (kf_strncat, kf_strlen, etc.) resolve to our local implementations instead of
 * calling kernel functions indirectly — avoiding kCFI type-hash mismatches. */
static struct {
    const char *name;
    unsigned long addr;
    bool is_func;  /* true = function ptr (needs GOT wrapping); false = data (OK as-is) */
} local_syms[] = {
    {"kpver",                0, false},
    {"kver",                 0, false},
    {"compat_copy_to_user",  0, true},
    {"strlen",               0, true},
    {"strncat",              0, true},
    {"strncpy",              0, true},
    {"strcpy",               0, true},
    {"memcpy",               0, true},
    {"memmove",              0, true},
    {"memset",               0, true},
    {"memcmp",               0, true},
    {"strcmp",               0, true},
    {"hook_wrap",            0, true},
    {"unhook",               0, true},
    {"fp_wrap_syscalln",     0, true},
    {"fp_unwrap_syscalln",   0, true},
    {"inline_wrap_syscalln", 0, true},
    {"inline_unwrap_syscalln",0, true},
    {"compat_strncpy_from_user",0, true},
    {"kallsyms_lookup_name", 0, true},
    {"has_syscall_wrapper",  0, false},
    /* printk: extern void (*printk)(...); KPM dereferences this ptr */
    {"printk",               0, false},
    /* hook_unwrap_remove: chain-based unhook with remove flag */
    {"hook_unwrap_remove",   0, true},
    /* KernelPatch asm/current.h compat: extern ints for get_current() */
    {"sp_el0_is_current",          0, false},
    {"thread_info_in_task",        0, false},
    {"sp_el0_is_thread_info",      0, false},
    {"thread_size",                0, false},
    {"task_in_thread_info_offset", 0, false},
    {NULL, 0, false}
};

/* Forward-declared: defined later in this section */
static unsigned long kallsyms_lookup(const char *name);

/* Forward declarations for KP compat layer (defined in Section 8b) */
static long kp_hook_wrap(void *func, int argno, void *before, void *after, void *udata);
static void kp_unhook(void *func);
static void kp_hook_unwrap_remove(void *func, void *before, void *after, int remove);
static long kp_fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata);
static void kp_fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after);
static long kp_inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata);
static void kp_inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after);
static long kp_compat_strncpy_from_user(char *dest, const char __user *src, long count);
static unsigned long kp_kallsyms_lookup_name(const char *name);
/* kp_has_syscall_wrapper int — address assigned dynamically in kp_syscall_hook_init */

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
    local_syms[12].addr = (unsigned long)&kp_hook_wrap;
    local_syms[13].addr = (unsigned long)&kp_unhook;
    local_syms[14].addr = (unsigned long)&kp_fp_wrap_syscalln;
    local_syms[15].addr = (unsigned long)&kp_fp_unwrap_syscalln;
    local_syms[16].addr = (unsigned long)&kp_inline_wrap_syscalln;
    local_syms[17].addr = (unsigned long)&kp_inline_unwrap_syscalln;
    local_syms[18].addr = (unsigned long)&kp_compat_strncpy_from_user;
    kp_kallsyms_lookup_name_ptr = kp_kallsyms_lookup_name;
    local_syms[19].addr = (unsigned long)&kp_kallsyms_lookup_name_ptr;
    local_syms[20].addr = (unsigned long)&kp_has_syscall_wrapper;
    /* printk: local_syms[21] is consumed by TWO paths:
     * 1. GOT fill (KP KPMs declaring extern void (*printk)(...)):
     *    KPM does MOV(addr) + LDR + BLR, so GOT slot needs &kp_printk_ptr.
     * 2. lookup_symbol API (KPM calls loader_api.lookup_symbol("printk")):
     *    KPM BLRs to the returned value directly, so we must return the
     *    actual printk function address, not a pointer-to-pointer.
     *
     * For the loader_api.lookup_symbol path (the hot path for non-KP KPMs),
     * return the real callable address. KP KPMs that need &kp_printk_ptr
     * go through the GOT fill path which wraps via kf_wrap_pool in
     * kpm_build_got. */
    kp_printk_ptr = (typeof(kp_printk_ptr))klog;
    local_syms[21].addr = (unsigned long)&kp_printk_ptr;
    local_syms[22].addr = (unsigned long)&kp_hook_unwrap_remove;
    local_syms[23].addr = (unsigned long)&kp_sp_el0_is_current;
    local_syms[24].addr = (unsigned long)&kp_thread_info_in_task;
    local_syms[25].addr = (unsigned long)&kp_sp_el0_is_thread_info;
    local_syms[26].addr = (unsigned long)&kp_thread_size;
    local_syms[27].addr = (unsigned long)&kp_task_in_thread_info_offset;

    /* Detect kernel version.
     * Strategy 1: linux_banner (char array, most reliable across GKI versions)
     * Strategy 2: init_uts_ns.name.release (struct offset varies with kref/padding)
     * Format: "Linux version 5.10.198-android12-..." → parse major.minor.patch */
    int major = 0, minor = 0, patch = 0;
    const char *release = 0;

    /* linux_banner is a char array: const char linux_banner[] = "Linux version ...";
     * kallsyms_lookup returns the address of the array, which IS the string. */
    unsigned long banner_addr = kallsyms_lookup("linux_banner");
    if (banner_addr) {
        const char *b = (const char *)banner_addr;
        const char *prefix = "Linux version ";
        const char *p = b;
        while (*prefix && *p == *prefix) { p++; prefix++; }
        if (!*prefix) release = p;
    }

    if (!release) {
        /* struct uts_namespace { struct kref kref; struct new_utsname name; ... };
         * kref = atomic_t = 4 bytes on ARM64; name.release at offset 4+130 = 134.
         * Try multiple offsets (older kernels omit kref at offset 0). */
        unsigned long uts_addr = kallsyms_lookup("init_uts_ns");
        if (uts_addr) {
            int offsets[] = { 130, 134, 4+130, 8+130, 0 };
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

/* Check local symbol table before falling through to kernel symbol lookup */
static unsigned long local_sym_lookup(const char *name)
{
    for (int i = 0; local_syms[i].name; i++)
        if (strcmp(name, local_syms[i].name) == 0)
            return local_syms[i].addr;
    return 0;
}

/* Check if addr matches a data-type local_sym entry.
 * Data entries (int vars like has_syscall_wrapper) already have
 * variable addresses and must NOT be wrapped for GOT double-deref.
 * Function entries return false — they need wrapping. */
static bool is_local_data_sym(unsigned long addr)
{
    for (int i = 0; local_syms[i].name; i++)
        if (!local_syms[i].is_func && local_syms[i].addr == addr)
            return true;
    return false;
}

/* Forward decl — defined below with noinline to prevent LTO inlining
 * of the indirect call into callers (Pitfall #21: PXN fault). */
__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long __kallsyms_lookup_named(const char *name);

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long kallsyms_lookup(const char *name)
{
    /* Cached kernel symbols (hot path) */
    if (strcmp(name, "module_alloc") == 0 && cached_module_alloc)
        return cached_module_alloc;
    if (strcmp(name, "aarch64_insn_patch_text_nosync") == 0 && cached_insn_patch)
        return cached_insn_patch;
    if ((strcmp(name, "__flush_icache_range") == 0 || strcmp(name, "flush_icache_range") == 0)
        && cached_flush_icache)
        return cached_flush_icache;

    /* Local loader-provided symbols (kpver, kver, compat_copy_to_user) */
    {
        unsigned long local = local_sym_lookup(name);
        if (local) return local;
    }

    /* Delegate to an out-of-line helper so LTO cannot inline the
     * indirect call and confuse the function-pointer variable with
     * its .bss address.  (Pitfall #21: LTO folds static fn ptr to
     * NULL init → skips LDR → blr jumps to data page → PXN fault.) */
    return __kallsyms_lookup_named(name);
}

/* noinline: prevents LTO from inlining this into callers where the
 * function-pointer deref may be miscompiled.   no_sanitize("cfi"), no_sanitize("kcfi"):
 * kallsyms_lookup_name is kCFI; CFI_ICALL check would mismatch. */
__attribute__((noinline, no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long __kallsyms_lookup_named(const char *name)
{
    if (kallsyms_lookup_name_fn) {
        return kallsyms_lookup_name_fn(name);
    }
    return 0;
}

/* CFI-protected wrappers for calling functions that may not have
 * matching CFI type hashes:
 * - vmlinux functions use kCFI, not our module's CFI_ICALL
 * - KPM functions may be compiled without CFI instrumentation
 * Without no_sanitize("cfi"), no_sanitize("kcfi"), the type-hash mismatch causes a panic. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void *call_module_alloc(unsigned long size)
{
    typedef void *(*fn_t)(unsigned long);
    return ((fn_t)cached_module_alloc)(size);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void call_flush_icache(unsigned long start, unsigned long end)
{
    typedef void (*flush_fn_t)(unsigned long, unsigned long);
    ((flush_fn_t)cached_flush_icache)(start, end);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int call_set_memory_x(unsigned long addr, int numpages)
{
    typedef int (*fn_t)(unsigned long, int);
    return ((fn_t)cached_set_memory_x)(addr, numpages);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int call_set_memory_rw(unsigned long addr, int numpages)
{
    typedef int (*fn_t)(unsigned long, int);
    return ((fn_t)cached_set_memory_rw)(addr, numpages);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int call_insn_patch(void *addr, u32 insn)
{
    typedef int (*fn_t)(void *, u32);
    return ((fn_t)cached_insn_patch)(addr, insn);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int kpm_drain_cpu(void *arg)
{
    (void)arg;
    /* Per-CPU I-cache invalidate.  QEMU TCG does not reliably
     * emulate broadcast ic ialluis across vCPUs, so each CPU
     * must flush its own instruction cache explicitly.
     * Without this, a vCPU can continue executing a cached
     * trampoline that branches into now-freed KPM pages. */
    asm volatile("ic iallu\n\t" "dsb ish\n\t" "isb\n\t" ::: "memory");
    return 0;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int call_stop_machine(int (*fn)(void *), void *data)
{
    typedef int (*st_fn_t)(int (*)(void *), void *, const void *);
    return ((st_fn_t)cached_stop_machine)(fn, data, (const void *)0);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void call_synchronize_rcu(void)
{
    typedef void (*fn_t)(void);
    ((fn_t)cached_synchronize_rcu)();
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static struct file *call_filp_open(const char *path, int flags, int mode)
{
    typedef struct file *(*fn_t)(const char *, int, int);
    return ((fn_t)cached_filp_open)(path, flags, mode);
}

/* KPM function pointer wrappers — KPMs may be compiled without CFI,
 * so calling through their function pointers also needs protection. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long call_kpm_ctl0(kpm_ctl0call_t fn, const char *args,
                          char *out_msg, int outlen)
{
    return fn(args, out_msg, outlen);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long call_kpm_exit(kpm_exitcall_t fn, void *reserved)
{
    klog("kpm_loader: call_kpm_exit fn=%px reserved=%px\n", fn, reserved);
    return fn(reserved);
}

/* ---- Strategy: kprobe ---- */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long strat_kprobe_kallsyms(void)
{
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    int rc = register_kprobe(&kp);
    if (rc < 0) return 0;
    unsigned long addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/* ---- Strategy: sprintf %ps scanning ---- */
#define KSYM_NAME_LEN 128
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long strat_sprintf_scan(void)
{
    extern int snprintf(char *buf, unsigned long size, const char *fmt, ...);
    char buf[KSYM_NAME_LEN];

    /* sprint_symbol is near the kernel base; mask off low 24 bits
     * to get the kernel start address, then scan upward.
     * vfree is a strong extern — uses standard ADRP reloc, no GOT. */
    unsigned long kaddr = (unsigned long)vfree;
    kaddr &= 0xffffffffff000000;

    for (int i = 0; i < 0x200000; i++) {
        snprintf(buf, sizeof(buf), "%ps", (void *)kaddr);
        if (strncmp(buf, "kallsyms_lookup_name", 20) == 0)
            return kaddr;
        kaddr += 0x10;
    }
    return 0;
}

/* ---- Runtime printk resolution ----
 * Resolves printk (5.x) or _printk (6.x) via kallsyms_lookup_name.
 * Must be called AFTER kallsyms_lookup_name_fn is set.
 * No direct symbol references — avoids GOT relocations (type 311) on 5.10. */
__attribute__((no_sanitize("cfi")))
static void resolve_printk(void)
{
    if (klog) return;
    if (!kallsyms_lookup_name_fn) return;

    unsigned long addr = kallsyms_lookup_name_fn("printk");
    if (!addr) addr = kallsyms_lookup_name_fn("_printk");
    if (addr) klog = (typeof(klog))addr;
}

/* ---- Multi-strategy kallsyms resolution ----
 *
 * Tries strategies in priority order:
 *   1. kprobe (works on 2.6.9+, no userspace help needed, survives KASLR)
 *   2. fixup_ko-patched marker (fast, but needs KASLR-aware address at push time)
 *   3. sprintf %ps scanning (slow but reliable if kprobe unavailable)
 *
 * Fallback: module param / /proc write at runtime (kallsyms_lookup_name_fn
 * stays 0, user sets it via 'echo kaddr <hex> > /proc/kpm_loader').
 */
static void kallsyms_init(void)
{
    unsigned long addr = 0;

    /* Strategy 1: fixup_ko marker (fast, deterministic when available) */
    if (kallsyms_patch.addr != 0) {
        kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))kallsyms_patch.addr;
        resolve_printk();
        klog("kpm_loader: kallsyms_lookup_name at %llx (from fixup_ko patch)\n",
               (u64)kallsyms_patch.addr);
    }

    /* Strategy 2: kprobe (KASLR-proof, no userspace help needed) */
    if (!kallsyms_lookup_name_fn) {
        addr = strat_kprobe_kallsyms();
        if (addr) {
            kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))addr;
            resolve_printk();
            klog("kpm_loader: kallsyms_lookup_name at %llx (via kprobe)\n", (u64)addr);
        }
    }

    /* Strategy 3: sprintf %ps scan (slow but universal) */
    if (!kallsyms_lookup_name_fn) {
        addr = strat_sprintf_scan();
        if (addr) {
            kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))addr;
            resolve_printk();
            klog("kpm_loader: kallsyms_lookup_name at %llx (via %%ps scan)\n", (u64)addr);
        }
    }

    if (!kallsyms_lookup_name_fn) {
        /* klog may not be set yet — use early_printk or just return */
        return;
    }

    /* Preload all needed symbols */
    for (int i = 0; needed_syms[i]; i++) {
        unsigned long saddr = kallsyms_lookup(needed_syms[i]);
        if (!saddr) continue;

        klog("kpm_loader:   %s = %llx\n", needed_syms[i], (u64)saddr);

        if (strcmp(needed_syms[i], "module_alloc") == 0)
            cached_module_alloc = saddr;
        else if (strcmp(needed_syms[i], "aarch64_insn_patch_text_nosync") == 0)
            cached_insn_patch = saddr;
        else if (strcmp(needed_syms[i], "__flush_icache_range") == 0 && !cached_flush_icache)
            cached_flush_icache = saddr;
        else if (strcmp(needed_syms[i], "flush_icache_range") == 0 && !cached_flush_icache)
            cached_flush_icache = saddr;
        else if (strcmp(needed_syms[i], "set_memory_x") == 0)
            cached_set_memory_x = saddr;
        else if (strcmp(needed_syms[i], "set_memory_rw") == 0)
            cached_set_memory_rw = saddr;
        else if (strcmp(needed_syms[i], "stop_machine") == 0)
            cached_stop_machine = saddr;
        else if (strcmp(needed_syms[i], "synchronize_rcu") == 0)
            cached_synchronize_rcu = saddr;
        else if (strcmp(needed_syms[i], "printk_deferred") == 0)
            cached_printk_deferred = saddr;
        else if (strcmp(needed_syms[i], "_copy_to_user") == 0)
            cached_copy_to_user = saddr;
        else if (strcmp(needed_syms[i], "raw_copy_to_user") == 0)
            cached_raw_copy_to_user = saddr;
        else if (strcmp(needed_syms[i], "copy_to_user") == 0)
            cached_raw_copy_to_user = saddr;
        else if (strcmp(needed_syms[i], "__arch_copy_to_user") == 0)
            cached_arch_copy_to_user = saddr;
        else if (strcmp(needed_syms[i], "__copy_to_user") == 0)
            cached_legacy_copy_to_user = saddr;
        else if (strcmp(needed_syms[i], "__uaccess_ttbr0_enable") == 0 && !cached_ttbr0_enable)
            cached_ttbr0_enable = saddr;
        else if (strcmp(needed_syms[i], "__uaccess_ttbr0_disable") == 0 && !cached_ttbr0_disable)
            cached_ttbr0_disable = saddr;
        else if (strcmp(needed_syms[i], "strncpy_from_user") == 0)
            cached_strncpy_from_user = saddr;
        else if (strcmp(needed_syms[i], "__cfi_slowpath_diag") == 0 && !cached_cfi_slowpath)
            cached_cfi_slowpath = saddr;
        else if (strcmp(needed_syms[i], "__cfi_slowpath") == 0 && !cached_cfi_slowpath)
            cached_cfi_slowpath = saddr;
        else if (strcmp(needed_syms[i], "report_cfi_failure") == 0)
            cached_report_cfi_failure = saddr;
        else if (strcmp(needed_syms[i], "swapper_pg_dir") == 0)
            cached_swapper_pg_dir = saddr;
        else if (strcmp(needed_syms[i], "filp_open") == 0)
            cached_filp_open = saddr;
        else if (strcmp(needed_syms[i], "memstart_addr") == 0)
            cached_memstart_addr = saddr;
    }
}

/* Forward declaration — defined in Section 8 (hook engine) */
static long do_hook(void *func, void *replace, void **backup);
static void do_unhook(void *func);

/* =========================================================================
 * Section 5b: CFI bypass — hook __cfi_slowpath + report_cfi_failure
 *
 * KPMs are compiled WITHOUT CFI instrumentation, so calling through KPM
 * function pointers triggers CFI_ICALL failures.  We hook the kernel's CFI
 * slowpath and failure-reporting functions to skip checks for addresses
 * that fall within KPM-allocated memory regions.
 *
 * Based on KernelPatch kernel/patch/common/secpass.c
 * ========================================================================= */

enum bug_trap_type {
    BUG_TRAP_TYPE_NONE = 0,
    BUG_TRAP_TYPE_WARN = 1,
    BUG_TRAP_TYPE_BUG = 2,
};

struct pt_regs;

typedef void (*cfi_slowpath_fn)(u64 id, void *ptr, void *diag);

static cfi_slowpath_fn backup__cfi_slowpath = 0;
static bool should_cfi_pass(unsigned long target);
/* Bypass CFI only for KPM and thunk regions. Non-KPM failures still need the
 * original slowpath so we do not silently let broken kernel control flow
 * continue past a real mismatch. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void replace__cfi_slowpath(u64 id, void *ptr, void *diag)
{
    if (should_cfi_pass((unsigned long)ptr))
        return;

    if (backup__cfi_slowpath)
        backup__cfi_slowpath(id, ptr, diag);
}

static enum bug_trap_type (*backup_report_cfi_failure)(struct pt_regs *regs,
    unsigned long addr, unsigned long *target, u32 type) = 0;
/* Downgrade failures only for KPM/thunk targets. */
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

static int bypass_kcfi(void)
{
    if (cached_report_cfi_failure) {
        long err = do_hook((void *)cached_report_cfi_failure,
                          (void *)replace_report_cfi_failure,
                          (void **)&backup_report_cfi_failure);
        if (err) {
            klog("kpm_loader: hook report_cfi_failure at %llx failed: %ld\n",
                   (u64)cached_report_cfi_failure, err);
            return (int)err;
        }
        klog("kpm_loader: hooked report_cfi_failure at %llx\n",
               (u64)cached_report_cfi_failure);
    }

    if (cached_cfi_slowpath) {
        long err = do_hook((void *)cached_cfi_slowpath,
                          (void *)replace__cfi_slowpath,
                          (void **)&backup__cfi_slowpath);
        if (err) {
            klog("kpm_loader: hook __cfi_slowpath at %llx failed: %ld\n",
                   (u64)cached_cfi_slowpath, err);
            return (int)err;
        }
        klog("kpm_loader: hooked __cfi_slowpath at %llx\n",
               (u64)cached_cfi_slowpath);
    }

    if (!cached_report_cfi_failure && !cached_cfi_slowpath) {
        klog("kpm_loader: no CFI symbols found, bypass disabled\n");
    }

    return 0;
}

/* ---- printk hook demo ---- */
static int (*volatile backup_printk)(const char *fmt, ...) = 0;

/* Call printk_deferred via its cached address. printk_deferred uses irq_work
 * to defer output, avoiding logbuf_lock re-entry from within printk hooks. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void call_printk_deferred(const char *fmt)
{
    typedef void (*fn_t)(const char *fmt, ...);
    ((fn_t)cached_printk_deferred)(fmt);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static int replace_printk(const char *fmt, ...)
{
    int ret = backup_printk(fmt);

    /* Use printk_deferred for the extra line — it queues via irq_work
     * and won't deadlock when called from within a printk hook. */
    if (cached_printk_deferred)
        call_printk_deferred("kpm_loader: [HOOK] printk called\n");

    return ret;
}

static int do_hook_printk(void)
{
    if (backup_printk) return -1; /* already hooked */
    void *pk_target = (void *)klog;
    return (int)do_hook(pk_target, (void *)replace_printk,
                        (void **)&backup_printk);
}

static void do_unhook_printk(void)
{
    if (!backup_printk) return;
    void *pk_target = (void *)klog;
    do_unhook(pk_target);
    backup_printk = 0;
}

/* =========================================================================
 * Section 6: AArch64 ELF relocation engine
 *
 * Handles all standard AArch64 RELA relocation types.
 * Adapted from KernelPatch kernel/patch/module/relo.c
 * ========================================================================= */

#define AARCH64_INSN_IMM_26   1
#define AARCH64_INSN_IMM_19   2
#define AARCH64_INSN_IMM_16   3
#define AARCH64_INSN_IMM_14   4
#define AARCH64_INSN_IMM_12   5
#define AARCH64_INSN_IMM_9    6
#define AARCH64_INSN_IMM_ADR  7
#define AARCH64_INSN_IMM_MOVZ 8
#define AARCH64_INSN_IMM_MOVK 9

enum reloc_op { RELOC_OP_NONE, RELOC_OP_ABS, RELOC_OP_PREL, RELOC_OP_PAGE };

static u64 reloc_calc(enum reloc_op op, void *place, u64 val)
{
    switch (op) {
    case RELOC_OP_ABS:  return val;
    case RELOC_OP_PREL: return val - (u64)place;
    case RELOC_OP_PAGE: return (val & ~0xfffULL) - ((u64)place & ~0xfffULL);
    default:            return 0;
    }
}

static int reloc_data(enum reloc_op op, void *place, u64 val, int len)
{
    s64 sval = reloc_calc(op, place, val);
    u64 imm_mask = ((u64)1 << len) - 1;

    switch (len) {
    case 16: *(s16 *)place = (s16)sval; break;
    case 32: *(s32 *)place = (s32)sval; break;
    case 64: *(s64 *)place = (s64)sval; break;
    default: return -1;
    }
    /* Overflow check: top bits must match sign bit */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((u64)(sval + 1) > 2) return -1;
    return 0;
}

/* Encode immediate into AArch64 instruction */
static u32 insn_encode_imm(int type, u32 insn, u64 imm)
{
    u32 immlo, immhi, lomask, himask, mask;
    int shift;

    switch (type) {
    case 7: /* ADR */
        lomask = 0x3; himask = 0x7ffff;
        immlo = imm & lomask; imm >>= 2; immhi = imm & himask;
        imm = (immlo << 24) | immhi;
        mask = (lomask << 24) | himask; shift = 5;
        break;
    case 1: /* IMM_26 */ mask = BIT(26) - 1; shift = 0; break;
    case 2: /* IMM_19 */ mask = BIT(19) - 1; shift = 5; break;
    case 3: /* IMM_16 */ mask = BIT(16) - 1; shift = 5; break;
    case 4: /* IMM_14 */ mask = BIT(14) - 1; shift = 5; break;
    case 5: /* IMM_12 */ mask = BIT(12) - 1; shift = 10; break;
    case 6: /* IMM_9 */  mask = BIT(9) - 1;  shift = 12; break;
    default: return insn;
    }

    insn &= ~(mask << shift);
    insn |= (imm & mask) << shift;
    return insn;
}

static int reloc_insn_imm(enum reloc_op op, void *place, u64 val, int lsb, int len, int imm_type)
{
    s64 sval = reloc_calc(op, place, val);
    u64 imm_mask = (BIT(lsb + len) - 1) >> lsb;
    u64 imm = (sval >> lsb) & imm_mask;
    u32 insn = *(u32 *)place;
    insn = insn_encode_imm(imm_type, insn, imm);
    *(u32 *)place = insn;

    /* Overflow check: shift down by lsb so we check only the bits that
     * will be encoded in the instruction field, not the zero LSBs. */
    sval >>= lsb;
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((u64)(sval + 1) >= 2) return -1;
    return 0;
}

static int reloc_insn_movw(enum reloc_op op, void *place, u64 val, int lsb, int is_signed)
{
    u32 insn = *(u32 *)place;
    s64 sval = reloc_calc(op, place, val);
    sval >>= lsb;
    u64 imm = sval & 0xffff;

    if (is_signed) {
        insn &= ~(3 << 29);
        if ((s64)imm >= 0) { insn |= 2 << 29; }
        else { imm = ~imm; }
    }

    insn = insn_encode_imm(3 /*IMM_16*/, insn, imm);
    *(u32 *)place = insn;

    sval >>= 16;
    if (is_signed) { sval++; }
    if ((u64)sval > (is_signed ? 0ULL : 0ULL)) return -1;
    return 0;
}

static int apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab,
                               unsigned int symindex, unsigned int relsec,
                               u64 *got_map)
{
    Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
    unsigned long nrels = sechdrs[relsec].sh_size / sizeof(*rel);
    int ovf;
    bool overflow_check;
    u64 val;
    void *loc;
    Elf64_Sym *sym;

    for (unsigned int i = 0; i < nrels; i++) {
        loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
        sym = (Elf64_Sym *)sechdrs[symindex].sh_addr + ELF64_R_SYM(rel[i].r_info);
        val = sym->st_value + rel[i].r_addend;
        overflow_check = true;

        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_AARCH64_NONE:
            ovf = 0;
            break;
        /* Data relocations */
        case R_AARCH64_ABS64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
            break;
        case R_AARCH64_ABS32:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 32);
            break;
        case R_AARCH64_ABS16:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 16);
            break;
        case R_AARCH64_PREL64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
            break;
        case R_AARCH64_PREL32:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
            break;
        /* R_AARCH64_PLT32 (314): like PREL32 but from PLT. Emitted by -fPIC code.
         * Operation: S + A - P (identical to PREL32). */
        case 314 /* R_AARCH64_PLT32 */:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
            break;
        case R_AARCH64_PREL16:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
            break;
        /* MOVW relocations */
        case R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, 0);
            break;
        case R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, 0);
            break;
        case R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, 0);
            break;
        case R_AARCH64_MOVW_UABS_G3:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48, 0);
            break;
        case R_AARCH64_MOVW_SABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, 1);
            break;
        case R_AARCH64_MOVW_SABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, 1);
            break;
        case R_AARCH64_MOVW_SABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, 1);
            break;
        case R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, 0);
            break;
        case R_AARCH64_MOVW_PREL_G0:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, 1);
            break;
        /* Immediate relocations */
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
            overflow_check = false;
        case R_AARCH64_ADR_PREL_PG_HI21:
            ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, 7 /*ADR*/);
            break;
        case R_AARCH64_ADD_ABS_LO12_NC:
        case R_AARCH64_LDST8_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12, 5 /*IMM_12*/);
            break;
        case R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11, 5 /*IMM_12*/);
            break;
        case R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10, 5 /*IMM_12*/);
            break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, 5 /*IMM_12*/);
            break;
        case R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8, 5 /*IMM_12*/);
            break;
        case R_AARCH64_TSTBR14:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 14, 4 /*IMM_14*/);
            break;
        case R_AARCH64_CONDBR19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, 2 /*IMM_19*/);
            break;
        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, 1 /*IMM_26*/);
            break;
        /* GOT-based data relocations (from -fPIC code) */
        case 311 /* R_AARCH64_ADR_GOT_PAGE */:
            if (got_map) {
                int si = (int)ELF64_R_SYM(rel[i].r_info);
                val = got_map[si] + rel[i].r_addend;
            }
            ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, 7 /*ADR*/);
            break;
        case 312 /* R_AARCH64_LD64_GOT_LO12_NC */:
            overflow_check = false;
            if (got_map) {
                int si = (int)ELF64_R_SYM(rel[i].r_info);
                val = got_map[si] + rel[i].r_addend;
            }
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, 5 /*IMM_12*/);
            break;
        default:
            klog("kpm_loader: unsupported RELA type %llu\n",
                   (u64)ELF64_R_TYPE(rel[i].r_info));
            return -1;
        }

        if (overflow_check && ovf == -1) {
            klog("kpm_loader: overflow in reloc type %u val=%px loc=%px\n",
                   (u32)ELF64_R_TYPE(rel[i].r_info), (void *)val, loc);
            return -1;
        }
    }
    return 0;
}

/* =========================================================================
 * Section 7: KPM binary loader
 *
 * Parses an ET_REL AArch64 KPM file, allocates memory, applies relocations,
 * and calls the module's init function.
 * ========================================================================= */

static LIST_HEAD(kpm_modules);
static struct mutex kpm_lock;
static struct lock_class_key kpm_lock_key;

static struct kpm_module *find_module(const char *name)
{
    struct kpm_module *mod;
    list_for_each_entry(mod, &kpm_modules, list) {
        if (strcmp(mod->info.name, name) == 0) return mod;
    }
    return NULL;
}

/* Find the KPM whose text page contains the given address */
static struct kpm_module *find_module_by_text_addr(u64 addr)
{
    struct kpm_module *mod;
    list_for_each_entry(mod, &kpm_modules, list) {
        if (mod->text_size && addr >= (u64)mod->start &&
            addr < (u64)mod->start + mod->text_size)
            return mod;
    }
    return NULL;
}

static int find_section(Elf64_Shdr *sechdrs, unsigned int shnum,
                         char *secstrings, const char *name)
{
    for (unsigned int i = 1; i < shnum; i++) {
        if ((sechdrs[i].sh_flags & SHF_ALLOC) &&
            strcmp(secstrings + sechdrs[i].sh_name, name) == 0)
            return i;
    }
    return -1;
}

static void *get_section_ptr(const Elf64_Ehdr *hdr, Elf64_Shdr *shdr, int idx)
{
    return (void *)hdr + shdr[idx].sh_offset;
}

/* Get next key=value string from .kpm.info section */
static char *next_kpm_info_str(char *p, unsigned long *remaining)
{
    /* Skip current string */
    while (*p) {
        p++;
        if ((*remaining)-- <= 1) return NULL;
    }
    /* Skip null bytes */
    while (!*p) {
        p++;
        if ((*remaining)-- <= 1) return NULL;
    }
    return p;
}

static const char *get_modinfo_val(const char *base, unsigned long size, const char *key)
{
    unsigned long keylen = strlen(key);
    unsigned long remaining = size;
    char *p = (char *)base;

    while (p) {
        if (strncmp(p, key, keylen) == 0 && p[keylen] == '=')
            return p + keylen + 1;
        p = next_kpm_info_str(p, &remaining);
    }
    return NULL;
}

struct kpm_load_info {
    const Elf64_Ehdr *hdr;
    unsigned long len;
    Elf64_Shdr *sechdrs;
    char *secstrings;
    char *strtab;
    int sym_idx, str_idx;
    int info_idx, init_idx, ctl0_idx, ctl1_idx, exit_idx;
    const char *name, *version, *license, *author, *description;
    u64 *got_map;      /* symbol_index → GOT slot address (0 if none) */
    void *got_base;    /* base of GOT slot array (vmalloc'd) */
    int got_count;     /* number of GOT slots allocated */
    u64 *kf_wrap_pool; /* u64 slots wrapping kf_ function addrs for GOT double-deref */
    int kf_wrap_count; /* slots used */
    int kf_wrap_max;   /* max slots */
};

/* Validate ELF header */
static int kpm_elf_check(struct kpm_load_info *info)
{
    const Elf64_Ehdr *hdr = info->hdr;

    if (info->len < sizeof(*hdr)) return -1;
    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG)) return -1;
    if (hdr->e_type != ET_REL) return -1;
    if (hdr->e_machine != EM_AARCH64) return -1;
    if (hdr->e_shentsize != sizeof(Elf64_Shdr)) return -1;
    if (hdr->e_shoff >= info->len) return -1;
    if (hdr->e_shnum * sizeof(Elf64_Shdr) > info->len - hdr->e_shoff) return -1;

    return 0;
}

/* Parse section headers and find KPM-specific sections */
static int kpm_setup_load_info(struct kpm_load_info *info)
{
    const Elf64_Ehdr *hdr = info->hdr;

    info->sechdrs = (void *)hdr + hdr->e_shoff;
    info->secstrings = (void *)hdr + info->sechdrs[hdr->e_shstrndx].sh_offset;

    /* Find .kpm.init and .kpm.exit (mandatory) */
    info->init_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.init");
    info->exit_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.exit");
    if (info->init_idx < 0 || info->exit_idx < 0) {
        klog("kpm_loader: missing .kpm.init or .kpm.exit\n");
        return -1;
    }

    /* Find .kpm.info (mandatory) */
    info->info_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.info");
    if (info->info_idx < 0) {
        klog("kpm_loader: missing .kpm.info section\n");
        return -1;
    }

    /* Parse metadata from .kpm.info */
    const char *info_base = get_section_ptr(hdr, info->sechdrs, info->info_idx);
    unsigned long info_size = info->sechdrs[info->info_idx].sh_size;

    info->name = get_modinfo_val(info_base, info_size, "name");
    info->version = get_modinfo_val(info_base, info_size, "version");
    info->license = get_modinfo_val(info_base, info_size, "license");
    info->author = get_modinfo_val(info_base, info_size, "author");
    info->description = get_modinfo_val(info_base, info_size, "description");

    if (!info->name || !info->version) {
        klog("kpm_loader: module name or version not found\n");
        return -1;
    }

    /* optional ctl sections */
    info->ctl0_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.ctl0");
    info->ctl1_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.ctl1");

    /* Find symbol table */
    for (unsigned int i = 1; i < hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->sym_idx = i;
            info->str_idx = info->sechdrs[i].sh_link;
            info->strtab = (char *)hdr + info->sechdrs[info->str_idx].sh_offset;
            break;
        }
    }

    if (info->sym_idx == 0) {
        klog("kpm_loader: no symbol table\n");
        return -1;
    }

    /* apply_relocate_add accesses all sections via sechdrs[].sh_addr,
     * but non-SHF_ALLOC sections (symtab, strtab, rela.*) don't get
     * sh_addr set during layout.  Point them at their file data. */
    for (unsigned int i = 0; i < hdr->e_shnum; i++) {
        if (!info->sechdrs[i].sh_addr)
            info->sechdrs[i].sh_addr = (Elf64_Addr)((unsigned long)hdr + info->sechdrs[i].sh_offset);
    }

    return 0;
}

/* Calculate section layout in memory */
static unsigned long kpm_layout_sections(struct kpm_load_info *info,
                                          unsigned int *text_size,
                                          unsigned int *text_used,
                                          unsigned int *plt_offs)
{
    unsigned long total = 0;
    unsigned int shnum = info->hdr->e_shnum;

    /* Pass 1: executable sections */
    for (unsigned int i = 1; i < shnum; i++) {
        Elf64_Shdr *s = &info->sechdrs[i];
        if (!(s->sh_flags & SHF_ALLOC)) continue;
        if (!(s->sh_flags & SHF_EXECINSTR)) continue;
        unsigned long align = s->sh_addralign ?: 1;
        total = ALIGN(total, align);
        s->sh_entsize = total;
        total += s->sh_size;
    }
    *text_used = total;           /* actual bytes before PAGE_ALIGN */
    total = ALIGN(total, PAGE_SIZE);

    /* Reserve PLT space inside the executable region so set_memory_x
     * covers it together with .text in a single call. */
    *plt_offs = total;
    total += 32 * 4 * 4;          /* max 32 PLT stubs, 16 bytes each */
    total = ALIGN(total, PAGE_SIZE);
    *text_size = total;

    /* Pass 2: non-executable SHF_ALLOC sections */
    for (unsigned int i = 1; i < shnum; i++) {
        Elf64_Shdr *s = &info->sechdrs[i];
        if (!(s->sh_flags & SHF_ALLOC)) continue;
        if (s->sh_flags & SHF_EXECINSTR) continue;
        unsigned long align = s->sh_addralign ?: 1;
        total = ALIGN(total, align);
        s->sh_entsize = total;
        total += s->sh_size;
    }
    total = ALIGN(total, PAGE_SIZE);

    return total;
}

/* Copy sections to final memory locations */
static int kpm_move_sections(struct kpm_module *mod, struct kpm_load_info *info, void *base)
{
    unsigned int shnum = info->hdr->e_shnum;

    for (unsigned int i = 1; i < shnum; i++) {
        Elf64_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        void *dest = base + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        if (shdr->sh_type != SHT_NOBITS)
            memcpy(dest, (void *)info->hdr + shdr->sh_offset, shdr->sh_size);
        else
            memset(dest, 0, shdr->sh_size);

        /* Update sh_addr to runtime address */
        shdr->sh_addr = (unsigned long)dest;

        /* Look for KPM control sections and record their pointers */
        if (strcmp(".kpm.init", sname) == 0)
            mod->init = (kpm_initcall_t *)dest;
        else if (strcmp(".kpm.ctl0", sname) == 0)
            mod->ctl0 = (kpm_ctl0call_t *)dest;
        else if (strcmp(".kpm.ctl1", sname) == 0)
            mod->ctl1 = (kpm_ctl1call_t *)dest;
        else if (strcmp(".kpm.exit", sname) == 0)
            mod->exit = (kpm_exitcall_t *)dest;
        else if (strcmp(".kpm.info", sname) == 0)
            mod->info.base = (const char *)dest;
    }

    /* Fix up string pointers relative to info base.
     * info->name etc. point to file buffer at (hdr + sec_offset + str_offset).
     * We need to convert to runtime: mod->info.base + str_offset.
     * So subtract the absolute file offset (hdr + sec_offset), add runtime base. */
    {
        unsigned long info_sec_offset = info->sechdrs[info->info_idx].sh_offset;
        const char *info_file_base = (const char *)info->hdr + info_sec_offset;
        mod->info.name    = info->name    - info_file_base + mod->info.base;
        mod->info.version = info->version - info_file_base + mod->info.base;
        if (info->license) mod->info.license =
            info->license - info_file_base + mod->info.base;
        if (info->author) mod->info.author =
            info->author - info_file_base + mod->info.base;
        if (info->description) mod->info.description =
            info->description - info_file_base + mod->info.base;
    }

    klog("kpm_loader: move_sections done: name='%s' ver='%s'\n",
           mod->info.name, mod->info.version);

    return 0;
}

/* Resolve undefined symbols against kernel kallsyms */
static int kpm_simplify_symbols(struct kpm_module *mod, struct kpm_load_info *info)
{
    Elf64_Shdr *symsec = &info->sechdrs[info->sym_idx];
    Elf64_Sym *sym = (void *)symsec->sh_addr;
    unsigned long nsyms = symsec->sh_size / sizeof(Elf64_Sym);

    for (unsigned int i = 1; i < nsyms; i++) {
        const char *name = info->strtab + sym[i].st_name;

        switch (sym[i].st_shndx) {
        case SHN_ABS:
            break;
        case SHN_UNDEF:
            /* Resolve via kallsyms */
            {
                unsigned long addr = kallsyms_lookup(name);
                if (!addr) {
                    /* Also search for CFI jump table variant */
                    char cfi_name[128];
                    unsigned long nl = strlen(name);
                    if (nl < 120) {
                        memcpy(cfi_name, name, nl);
                        memcpy(cfi_name + nl, ".cfi_jt", 8);
                        addr = kallsyms_lookup(cfi_name);
                    }
                }
                if (!addr) {
                    /* KernelPatch KPM compatibility: symbols like kf_strncat
                     * are function pointers defined via kfunc_def. Strip the
                     * kf_ prefix and resolve the underlying kernel function.
                     *
                     * CRITICAL: kfunc_def creates function-pointer VARIABLES
                     * (e.g. typeof(strcmp) *kf_strcmp).  With -fPIC the KPM
                     * accesses them through GOT with a double dereference:
                     *   adrp → ldr [GOT] → ldr [var] → blr
                     * The GOT slot must contain the variable's ADDRESS, not
                     * the function address.  We allocate a u64 wrapper slot
                     * that holds the resolved function address, and return
                     * the wrapper's address as the symbol value. */
                    unsigned long nlen = strlen(name);
                    if (nlen > 3 && name[0] == 'k' && name[1] == 'f' && name[2] == '_') {
                        addr = kallsyms_lookup(name + 3);
                        if (addr) {
                            if (info->kf_wrap_pool &&
                                info->kf_wrap_count < info->kf_wrap_max) {
                                u64 *slot = &info->kf_wrap_pool[info->kf_wrap_count++];
                                *slot = addr;
                                addr = (unsigned long)slot;
                                klog("kpm_loader: wrapped %s -> %s slot=%px val=%llx\n",
                                       name, name + 3, slot, *slot);
                            }
                        }
                    }
                }
                if (!addr) {
                    klog("kpm_loader: undefined symbol: %s\n", name);
                    return -1;
                }
                sym[i].st_value = addr;
            }
            break;
        default:
            /* Adjust by section base */
            {
                unsigned int shndx = sym[i].st_shndx;
                if (shndx < info->hdr->e_shnum) {
                    sym[i].st_value += info->sechdrs[shndx].sh_addr;
                }
            }
            break;
        }
    }
    return 0;
}

/* Flush instruction cache for a range — defined below */
static void kpm_flush_icache(void *start, unsigned long size);
static void *kpm_alloc(unsigned long size);

/* Build GOT (Global Offset Table) for -fPIC KPMs.
 * -fPIC code generates ADR_GOT_PAGE + LD64_GOT_LO12 pairs for extern data.
 * Each pair needs a GOT slot: a u64 holding the symbol's absolute address.
 *   1. Scans all relocs for unique symbols needing GOT slots
 *   2. Allocates a u64 array via vmalloc
 *   3. Fills each slot with the resolved symbol address from st_value
 *   4. Builds got_map[sym_idx] → GOT slot address for the reloc handler
 */
static int kpm_build_got(struct kpm_module *mod, struct kpm_load_info *info)
{
    unsigned int shnum = info->hdr->e_shnum;
    int nsyms = (int)(info->sechdrs[info->sym_idx].sh_size / sizeof(Elf64_Sym));

    info->got_map = vmalloc(nsyms * sizeof(u64));
    if (!info->got_map) return -1;
    memset(info->got_map, 0, nsyms * sizeof(u64));
    info->got_count = 0;

    /* Pass 1: count unique symbols referenced via GOT relocs */
    for (unsigned int i = 1; i < shnum; i++) {
        if (info->sechdrs[i].sh_type != SHT_RELA) continue;
        unsigned int target = info->sechdrs[i].sh_info;
        if (target >= shnum) continue;
        if (!(info->sechdrs[target].sh_flags & SHF_ALLOC)) continue;

        Elf64_Rela *rel = (void *)info->sechdrs[i].sh_addr;
        unsigned long nrels = info->sechdrs[i].sh_size / sizeof(*rel);
        for (unsigned long r = 0; r < nrels; r++) {
            u32 type = (u32)ELF64_R_TYPE(rel[r].r_info);
            if (type == 311 || type == 312) {
                int sym_idx = (int)ELF64_R_SYM(rel[r].r_info);
                if (sym_idx > 0 && sym_idx < nsyms && !info->got_map[sym_idx]) {
                    info->got_map[sym_idx] = 1; /* mark needed */
                    info->got_count++;
                }
            }
        }
    }

    if (info->got_count == 0) {
        vfree(info->got_map);
        info->got_map = NULL;
        return 0;
    }

    /* Allocate slots via kpm_alloc so they're near the code (ADRP ±4GB range) */
    info->got_base = kpm_alloc(info->got_count * 8);
    if (!info->got_base) { vfree(info->got_map); info->got_map = NULL; return -1; }

    Elf64_Sym *syms = (void *)info->sechdrs[info->sym_idx].sh_addr;
    u64 *slot = (u64 *)info->got_base;
    klog("kpm_loader: GOT base=%px count=%d\n", info->got_base, info->got_count);
    for (int s = 0; s < nsyms; s++) {
        if (info->got_map[s]) {
            const char *sname = info->strtab + syms[s].st_name;
            u64 val = syms[s].st_value;
            /* -fPIC KPMs always double-deref through GOT:
             *   adrp→ldr[GOT]→ldr[var]→blr
             * The GOT slot must contain a variable ADDRESS, not a
             * function address.  For external (SHN_UNDEF) symbols that
             * resolve to functions, we allocate a u64 wrapper slot that
             * holds the real function address, and put the wrapper's
             * address in the GOT.  Data symbols (int vars like
             * has_syscall_wrapper) already have variable addresses in
             * GOT and must NOT be wrapped.  KPM-internal symbols
             * (non-SHN_UNDEF) have their own variable addresses. */
            bool need_wrap = false;
            if (syms[s].st_shndx == SHN_UNDEF) {
                /* Already wrapped by kf_ prefix path? skip double-wrap */
                bool already_wrapped = false;
                for (int w = 0; w < info->kf_wrap_count; w++) {
                    if (info->kf_wrap_pool[w] == val) { already_wrapped = true; break; }
                }
                if (!already_wrapped && !is_local_data_sym((unsigned long)val)) {
                    need_wrap = true;
                }
            }
            if (need_wrap) {
                if (info->kf_wrap_count >= info->kf_wrap_max) {
                    klog("kpm_loader: GOT-wrap pool exhausted (%d)\n",
                           info->kf_wrap_max);
                    return -1;
                }
                u64 *wslot = &info->kf_wrap_pool[info->kf_wrap_count++];
                *wslot = val;
                val = (u64)wslot;
                klog("kpm_loader: GOT-wrap %s -> slot=%px val=%llx\n",
                       sname, wslot, *wslot);
            }
            info->got_map[s] = (u64)slot;
            *slot++ = val;
            klog("kpm_loader: GOT[%d] slot=%px val=0x%llx sym='%s'\n",
                   s, (void *)info->got_map[s], val, sname);
        }
    }

    mod->got_base = info->got_base;
    return 0;
}

/* Generate a PLT stub at `entry` (16 bytes: ldr x16,.+8; br x16; .dword target).
 * Uses a literal pool entry so the stub can reach any 64-bit address.
 * ADRP (±4GB) is insufficient when the KPM and target are in different
 * kernel address regions (e.g. module_alloc vs vmalloc). */
static int plt_gen_entry(u32 *entry, unsigned long target)
{
    entry[0] = 0x58000050;  /* ldr x16, #8 (PC+8, imm19=2 words, skips BR) */
    entry[1] = 0xd61f0200;  /* br x16 */
    entry[2] = (u32)(target & 0xffffffffUL);
    entry[3] = (u32)(target >> 32);
    return 4;  /* 4 u32 words = 16 bytes */
}

/* Scan CALL26/JUMP26 relocations whose target is outside ±128MB branch range,
 * and redirect them to PLT stubs in the pre-allocated plt_base area.
 * Updates r_addend so sym->st_value + r_addend = plt_stub address.
 * Returns number of PLT entries generated, or -1 if PLT space exhausted. */
static int kpm_generate_plt(struct kpm_load_info *info, u32 *plt_base, int max_plt)
{
    int plt_count = 0;
    unsigned int shnum = info->hdr->e_shnum;

    for (unsigned int i = 1; i < shnum; i++) {
        if (info->sechdrs[i].sh_type != SHT_RELA) continue;
        unsigned int target_sec = info->sechdrs[i].sh_info;
        if (target_sec >= shnum) continue;
        if (!(info->sechdrs[target_sec].sh_flags & SHF_ALLOC)) continue;

        Elf64_Rela *rel = (void *)info->sechdrs[i].sh_addr;
        unsigned long nrels = info->sechdrs[i].sh_size / sizeof(*rel);

        for (unsigned int j = 0; j < nrels; j++) {
            unsigned int rtype = ELF64_R_TYPE(rel[j].r_info);
            if (rtype != R_AARCH64_CALL26 && rtype != R_AARCH64_JUMP26)
                continue;

            unsigned int symidx = ELF64_R_SYM(rel[j].r_info);
            Elf64_Sym *sym = (Elf64_Sym *)info->sechdrs[info->sym_idx].sh_addr + symidx;
            unsigned long target = sym->st_value + rel[j].r_addend;
            unsigned long site = info->sechdrs[target_sec].sh_addr + rel[j].r_offset;

            long offset = (long)(target - site);
            if (offset >= -(1L << 27) && offset < (1L << 27))
                continue;

            if (plt_count >= max_plt) {
                klog("kpm_loader: PLT overflow (%d needed)\n", plt_count + 1);
                return -1;
            }

            u32 *stub = plt_base + plt_count * 4;
            plt_gen_entry(stub, target);
            kpm_flush_icache(stub, 16);

            rel[j].r_addend = (long)((unsigned long)stub - sym->st_value);
            plt_count++;
        }
    }
    if (plt_count)
        klog("kpm_loader: generated %d PLT stub(s)\n", plt_count);
    return plt_count;
}

/* Apply all relocations */
static int kpm_apply_relocations(struct kpm_module *mod, struct kpm_load_info *info)
{
    unsigned int shnum = info->hdr->e_shnum;
    int total_rels = 0;

    for (unsigned int i = 1; i < shnum; i++) {
        unsigned int target = info->sechdrs[i].sh_info;
        if (target >= shnum) continue;
        if (!(info->sechdrs[target].sh_flags & SHF_ALLOC)) continue;

        if (info->sechdrs[i].sh_type == SHT_RELA) {
            total_rels++;
            int rc = apply_relocate_add(info->sechdrs, info->strtab, info->sym_idx, i, info->got_map);
            if (rc < 0) {
                klog("kpm_loader: reloc: section %u FAILED %d\n", i, rc);
                return rc;
            }
        }
    }
    klog("kpm_loader: applied %d relocation sections\n", total_rels);
    return 0;
}

/* Allocate memory for KPM sections (writable, not yet executable).
 * set_memory_x is deferred until after all patching is done. */
static void *kpm_alloc(unsigned long size)
{
    void *p;
    /* Prefer module_alloc but fall back to vmalloc.
     * On some 5.10 kernels, set_memory_x doesn't work on module_alloc'd
     * memory (the PTE change silently fails), so we force vmalloc for
     * broader compatibility. */
    int use_module_alloc = 0; /* FIX: module_alloc + set_memory_x broken on 5.10 */
    if (use_module_alloc && cached_module_alloc) {
        p = call_module_alloc(size);
    } else {
        p = vmalloc(size);
    }
    if (!p) return NULL;
    memset(p, 0, size);
    kpm_area_add((unsigned long)p, size);
    return p;
}

/* Make previously-allocated memory executable */
static void kpm_make_exec(void *p, unsigned long size)
{
    if (cached_set_memory_x) {
        int np = (int)((size + PAGE_SIZE - 1) / PAGE_SIZE);
        klog("kpm_loader: set_memory_x(%px, %d pages, %lu bytes) calling...\n", p, np, size);
        int rc = call_set_memory_x((unsigned long)p, np);
        klog("kpm_loader: set_memory_x returned %d\n", rc);
        if (rc)
            klog("kpm_loader: set_memory_x(%px, %d) FAILED: %d\n", p, np, rc);
    } else {
        klog("kpm_loader: set_memory_x NOT available, skipping!\n");
    }
}

static void kpm_free_exec(void *addr)
{
    if (addr)
        kpm_area_remove((unsigned long)addr);
    vfree(addr);
}

/* Flush instruction cache for the module's code range */
static void kpm_flush_icache(void *start, unsigned long size)
{
    if (cached_flush_icache)
        call_flush_icache((unsigned long)start, (unsigned long)start + size);
}

static struct kpm_api loader_api;

/* Load a KPM from a memory buffer */
static long load_kpm_from_data(const void *data, unsigned long len,
                                const char *args, const char *event, void *reserved)
{
    struct kpm_load_info load_info;
    memset(&load_info, 0, sizeof(load_info));
    load_info.hdr = data;
    load_info.len = len;

    if (kpm_elf_check(&load_info)) {
        klog("kpm_loader: invalid ELF header\n");
        return -1;
    }

    if (kpm_setup_load_info(&load_info)) {
        klog("kpm_loader: failed to parse KPM info\n");
        return -1;
    }

    klog("kpm_loader: loading module '%s' version %s\n",
           load_info.name, load_info.version);

    /* Check for duplicates */
    mutex_lock(&kpm_lock);
    if (find_module(load_info.name)) {
        klog("kpm_loader: module '%s' already loaded\n", load_info.name);
        mutex_unlock(&kpm_lock);
        return -2; /* -EEXIST */
    }
    mutex_unlock(&kpm_lock);

    /* Allocate module struct */
    struct kpm_module *mod = vmalloc(sizeof(*mod));
    if (!mod) return -3; /* -ENOMEM */
    memset(mod, 0, sizeof(*mod));

    /* Copy args if provided */
    if (args) {
        unsigned long alen = strlen(args);
        mod->args = vmalloc(alen + 1);
        if (mod->args) strcpy(mod->args, args);
    }

    /* Layout sections — PLT space reserved inside executable region */
    unsigned int text_size, text_used, plt_offs;
    mod->size = kpm_layout_sections(&load_info, &text_size, &text_used, &plt_offs);
    mod->text_size = text_size;
    mod->text_used = text_used;
    unsigned long plt_max = 32;

    mod->start = kpm_alloc(mod->size);
    if (!mod->start) {
        klog("kpm_loader: failed to allocate %u bytes\n", mod->size);
        kpm_free_exec(mod->start);
        vfree(mod);
        return -3;
    }
    memset(mod->start, 0, mod->size);

    /* Move sections to final locations */
    if (kpm_move_sections(mod, &load_info, mod->start)) {
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }
    /* Simplify symbols (resolve undefined) */
    {
        load_info.kf_wrap_max = 128;
        load_info.kf_wrap_pool = vmalloc(load_info.kf_wrap_max * sizeof(u64));
        load_info.kf_wrap_count = 0;
    }
    if (kpm_simplify_symbols(mod, &load_info)) {
        if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }

    /* Build GOT for -fPIC KPMs (ADR_GOT_PAGE / LD64_GOT_LO12 relocs) */
    if (kpm_build_got(mod, &load_info)) {
        klog("kpm_loader: GOT build FAILED\n");
        if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }

    /* Generate PLT stubs for far-away CALL26/JUMP26 targets.
     * PLT space was reserved inside the executable region by
     * kpm_layout_sections, so no separate set_memory_x needed. */
    int plt_stubs = 0;
    unsigned long plt_area_addr = 0;
    {
        u32 *plt_base = (u32 *)((char *)mod->start + plt_offs);
        int nplt = kpm_generate_plt(&load_info, plt_base, (int)plt_max);
        if (nplt < 0) {
            if (load_info.got_base) kpm_free_exec(load_info.got_base);
            if (load_info.got_map) vfree(load_info.got_map);
            if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
            kpm_free_exec(mod->start);
            vfree(mod);
            return -1;
        }
        if (nplt > 0) {
            klog("kpm_loader: generated %d PLT stub(s)\n", nplt);
            plt_stubs = nplt;
            plt_area_addr = (unsigned long)plt_base;
        }
    }
    klog("kpm_loader: PLT done, about to relocate\n");

    /* Apply relocations */
    if (kpm_apply_relocations(mod, &load_info)) {
        klog("kpm_loader: relocation FAILED\n");
        if (load_info.got_base) kpm_free_exec(load_info.got_base);
        if (load_info.got_map) vfree(load_info.got_map);
        if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }
    /* GOT map no longer needed after relocs are applied,
     * but kf_wrap_pool stays alive until KPM init completes. */
    if (load_info.got_map) { vfree(load_info.got_map); load_info.got_map = NULL; }
    klog("kpm_loader: relocations applied, about to make exec\n");
    /* DEBUG: dump .kpm.init raw bytes after relocation */
    {
        unsigned int shnum = load_info.hdr->e_shnum;
        for (unsigned int i = 1; i < shnum; i++) {
            const char *sname = load_info.secstrings + load_info.sechdrs[i].sh_name;
            if (strcmp(".kpm.init", sname) == 0) {
                u64 *raw = (u64 *)(unsigned long)load_info.sechdrs[i].sh_addr;
                klog("kpm_loader: DEBUG .kpm.init sh_addr=%llx raw[0]=0x%llx\n",
                       (u64)load_info.sechdrs[i].sh_addr, raw[0]);
            }
            if (strcmp(".kpm.exit", sname) == 0) {
                u64 *raw = (u64 *)(unsigned long)load_info.sechdrs[i].sh_addr;
                klog("kpm_loader: DEBUG .kpm.exit sh_addr=%llx raw[0]=0x%llx\n",
                       (u64)load_info.sechdrs[i].sh_addr, raw[0]);
            }
        }
        /* Also dump the .text section symbol value */
        Elf64_Shdr *symsec = &load_info.sechdrs[load_info.sym_idx];
        Elf64_Sym *sym = (void *)symsec->sh_addr;
        klog("kpm_loader: DEBUG sym[27]=.text st_value=0x%llx shndx=%d\n",
               sym[27].st_value, sym[27].st_shndx);
    }

    /* Fixup: convert LDR→ADD for -fno-PIC function call pattern.
     * ET_REL objects compiled with -fno-PIC generate:
     *   adrp xN, page(sym)
     *   ldr  xM, [xN, #lo12]    // expects GOT entry, loads from kernel text
     *   blr  xM                  // crashes — instructions treated as pointer
     * After relocation, ADRP gives page_of(sym_addr) and LDR loads from that
     * page+lo12, which reads the function's own code bytes as a pointer.
     * We convert LDR to ADD so xM = page + offset = function address directly.
     *
     * CRITICAL: use the relocation entry's sym_value directly for the ADD
     * immediate rather than extracting the scaled LDR immediate and scaling
     * back. LDR64 stores imm=(sym_val>>3)&0x1FF; <<3 loses bits [2:0] of the
     * page offset, causing the ADD to compute sym_val&~7 (off by up to 4 bytes
     * — right onto the kCFI type hash on 4-byte-aligned functions). */
    {
        unsigned int shnum = load_info.hdr->e_shnum;
        int fixed = 0;
        for (unsigned int i = 1; i < shnum; i++) {
            if (load_info.sechdrs[i].sh_type != SHT_RELA) continue;
            unsigned int target_sec = load_info.sechdrs[i].sh_info;
            if (target_sec >= shnum) continue;
            if (!(load_info.sechdrs[target_sec].sh_flags & SHF_ALLOC)) continue;
            u32 *sec_base = (u32 *)(unsigned long)load_info.sechdrs[target_sec].sh_addr;
            unsigned long sec_end = (unsigned long)sec_base + load_info.sechdrs[target_sec].sh_size;

            Elf64_Word symindex = load_info.sechdrs[i].sh_link;
            Elf64_Rela *rel = (void *)load_info.sechdrs[i].sh_addr;
            unsigned long nrels = load_info.sechdrs[i].sh_size / sizeof(*rel);
            for (unsigned int j = 0; j < nrels; j++) {
                if (ELF64_R_TYPE(rel[j].r_info) != R_AARCH64_LDST64_ABS_LO12_NC)
                    continue;
                u32 *loc = (u32 *)((unsigned long)sec_base + rel[j].r_offset);
                u32 insn = *loc;
                /* 64-bit LDR unsigned immediate: mask 0xFFC00000, pattern 0xF9400000 */
                if ((insn & 0xFFC00000) != 0xF9400000) continue;
                /* Only convert for function symbols (STT_FUNC / STT_NOTYPE).
                 * OBJECT (e.g. function-pointer variables) and SECTION symbols
                 * must keep the LDR — it reads a stored pointer value. */
                {
                    Elf64_Sym *ck_sym = (Elf64_Sym *)load_info.sechdrs[symindex].sh_addr
                                        + ELF64_R_SYM(rel[j].r_info);
                    unsigned char stt = ELF64_ST_TYPE(ck_sym->st_info);
                    if (stt == STT_OBJECT || stt == STT_SECTION)
                        continue;
                }
                unsigned int ldst_reg = insn & 0x1F;
                int converted = 0;
                /* Look ahead up to 16 instructions for BLR/BR through same reg */
                for (int k = 1; k <= 16 && !converted; k++) {
                    u32 *next = loc + k;
                    if ((unsigned long)next >= sec_end) break;
                    u32 next_insn = *next;
                    /* If any intermediate instruction writes the register,
                     * the LDR→BLR chain is broken — do not convert.
                     * E.g. LDR x8,[x21]; ... LDR x8,[x8,#40]; BLR x8
                     * where the second LDR overwrites x8 before the call. */
                    if ((next_insn & 0x1F) == ldst_reg && next_insn != insn)
                        break;
                    /* BLR Xn: 0xD63F0000 | (n<<5), mask 0xFFFFFC1F */
                    if ((next_insn & 0xFFFFFC1F) == 0xD63F0000 &&
                        (unsigned int)((next_insn >> 5) & 0x1F) == ldst_reg) {
                        /* Use sym_value from relocation entry: preserves bits [2:0] */
                        Elf64_Sym *r_sym = (Elf64_Sym *)load_info.sechdrs[symindex].sh_addr
                                           + ELF64_R_SYM(rel[j].r_info);
                        u64 sym_val = r_sym->st_value + rel[j].r_addend;
                        unsigned int add_imm12 = sym_val & 0xFFF;
                        u32 new_insn = 0x91000000 | (add_imm12 << 10) | (insn & 0x3FF);
                        *loc = new_insn;
                        fixed++;
                        converted = 1;
                    }
                    /* BR Xn: 0xD61F0000 | (n<<5), mask 0xFFFFFC1F */
                    if (!converted &&
                        (next_insn & 0xFFFFFC1F) == 0xD61F0000 &&
                        (unsigned int)((next_insn >> 5) & 0x1F) == ldst_reg) {
                        Elf64_Sym *r_sym = (Elf64_Sym *)load_info.sechdrs[symindex].sh_addr
                                           + ELF64_R_SYM(rel[j].r_info);
                        u64 sym_val = r_sym->st_value + rel[j].r_addend;
                        unsigned int add_imm12 = sym_val & 0xFFF;
                        u32 new_insn = 0x91000000 | (add_imm12 << 10) | (insn & 0x3FF);
                        *loc = new_insn;
                        fixed++;
                        converted = 1;
                    }
                }
            }
        }
        if (fixed) klog("kpm_loader: fixed %d LDR->ADD for function calls\n", fixed);
    }

    /* Dump first 12 words of code for debugging */
    {
        u32 *code = (u32 *)mod->start;
        klog("kpm_loader: code[0..11]=%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
               code[0], code[1], code[2], code[3], code[4], code[5],
               code[6], code[7], code[8], code[9], code[10], code[11]);
    }

    /* Make executable pages RX — includes .text and PLT stubs (both inside text_size) */
    kpm_make_exec(mod->start, text_size);

    /* Flush instruction cache for executable sections */
    kpm_flush_icache(mod->start, text_size);
    if (plt_stubs > 0)
        klog("kpm_loader: PLT %d stubs @ %lx (inside exec region)\n",
             plt_stubs, plt_area_addr);

    klog("kpm_loader: icache flushed, about to call KPM init\n");

    /* Dump GOT contents to verify they survived relocation */
    if (load_info.got_base && load_info.got_count) {
        u64 *got = (u64 *)load_info.got_base;
        klog("kpm_loader: GOT dump (%d entries @ %px):\n",
               load_info.got_count, load_info.got_base);
        for (int g = 0; g < load_info.got_count; g++) {
            klog("kpm_loader:   GOT[%d] @ %px = 0x%llx\n",
                   g, &got[g], got[g]);
        }
    }

    /* Now dereference the function pointers from the patched sections */
    klog("kpm_loader: mod->init=%px *mod->init=%px mod->exit=%px\n",
           mod->init, mod->init ? *(void **)mod->init : 0, mod->exit);
    /* Dump loader_api and the reserved pointer */
    klog("kpm_loader: &loader_api=%px reserved=%px\n", &loader_api, reserved);
    klog("kpm_loader: loader_api fields: sym=%px load=%px unload=%px hook=%px unhook=%px printk=%px\n",
           loader_api.lookup_symbol, loader_api.load_kpm, loader_api.unload_kpm,
           loader_api.hook, loader_api.unhook, loader_api.printk);
    /* Dump KPM .bss contents (api and kernel_printk globals) */
    {
        unsigned int shnum = load_info.hdr->e_shnum;
        for (unsigned int i = 1; i < shnum; i++) {
            const char *sname = load_info.secstrings + load_info.sechdrs[i].sh_name;
            if (strcmp(".bss", sname) == 0) {
                u64 *bss = (u64 *)(unsigned long)load_info.sechdrs[i].sh_addr;
                klog("kpm_loader: KPM .bss at %px: [0]=0x%llx [8]=0x%llx\n", bss, bss[0], bss[1]);
            }
        }
    }
    long rc = 0;
    /* DEBUG: explicitly write loader_api to KPM .bss[0] before calling init */
    {
        unsigned int shnum = load_info.hdr->e_shnum;
        for (unsigned int i = 1; i < shnum; i++) {
            const char *sname = load_info.secstrings + load_info.sechdrs[i].sh_name;
            if (strcmp(".bss", sname) == 0) {
                u64 *bss = (u64 *)(unsigned long)load_info.sechdrs[i].sh_addr;
                bss[0] = (u64)reserved;
                klog("kpm_loader: pre-set .bss[0] = %px\n", reserved);
            }
        }
        /* Dump relocated instructions around key offsets */
        u32 *code_dump = (u32 *)mod->start;
        klog("kpm_loader: code[18]=%08x code[28]=%08x code[30]=%08x code[48]=%08x\n",
               code_dump[0x18/4], code_dump[0x28/4], code_dump[0x30/4], code_dump[0x48/4]);
    }
    /* Add to loaded modules list BEFORE init so hook_alloc can find
     * the KPM text page for trampoline placement. */
    mod->got_base = load_info.got_base;
    load_info.got_base = NULL;
    mutex_lock(&kpm_lock);
    list_add_tail(&mod->list, &kpm_modules);
    mutex_unlock(&kpm_lock);

    /* DEBUG: skip init call to test if crash is in init or in loader */
    if (1 && mod->init && *mod->init) {
        /* Read raw function pointer as u64 to avoid LTO type-based issues */
        u64 volatile fn_addr = *(u64 *)mod->init;
        kpm_initcall_t init_fn = (kpm_initcall_t)fn_addr;
        klog("kpm_loader: calling init_fn at %px (raw=0x%llx)\n", init_fn, fn_addr);
        rc = init_fn(mod->args, event, reserved);
        klog("kpm_loader: init_fn returned %ld\n", rc);
        /* Dump KPM .bss after init */
        {
            unsigned int shnum = load_info.hdr->e_shnum;
            for (unsigned int i = 1; i < shnum; i++) {
                const char *sname = load_info.secstrings + load_info.sechdrs[i].sh_name;
                if (strcmp(".bss", sname) == 0) {
                    u64 *bss = (u64 *)(unsigned long)load_info.sechdrs[i].sh_addr;
                    klog("kpm_loader: KPM .bss after init at %px: [0]=0x%llx [8]=0x%llx\n", bss, bss[0], bss[1]);
                }
            }
        }
        if (rc != 0) {
            klog("kpm_loader: KPM init returned error %ld, unloading\n", rc);
            mutex_lock(&kpm_lock);
            list_del(&mod->list);
            mutex_unlock(&kpm_lock);
            if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
            kpm_free_exec(mod->start);
            if (mod->args) vfree(mod->args);
            vfree(mod);
            return rc;
        }
        klog("kpm_loader: KPM loaded successfully\n");
    } else if (!mod->init || !*mod->init) {
        klog("kpm_loader: no init function found\n");
        mutex_lock(&kpm_lock);
        list_del(&mod->list);
        mutex_unlock(&kpm_lock);
        if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
        kpm_free_exec(mod->start);
        if (mod->args) vfree(mod->args);
        vfree(mod);
        return -1;
    }

    /* kf_wrap_pool no longer needed after init — GOT wrappers live
     * inside the GOT slots which stay with mod->got_base. */
    if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
    load_info.kf_wrap_pool = NULL;
    return 0;
}

/* Load a KPM from a file path */
static long load_kpm_file(const char *path, const char *args, void *reserved)
{
    if (!path) return -1;

    if (!cached_filp_open) return -2;
    struct file *filp = call_filp_open(path, O_RDONLY, 0);
    if (!filp || (unsigned long)filp >= 0xfffffffffffff000UL) {
        klog("kpm_loader: cannot open %s\n", path);
        return (long)filp;
    }

    long long size = vfs_llseek(filp, 0, 2); /* SEEK_END */
    if (size <= 0) {
        klog("kpm_loader: vfs_llseek %s returned %lld\n", path, size);
        filp_close(filp, NULL);
        return -1;
    }

    void *data = vmalloc(size);
    if (!data) {
        klog("kpm_loader: vmalloc(%lld) failed for %s\n", size, path);
        filp_close(filp, NULL);
        return -3;
    }

    long long pos = 0;
    vfs_llseek(filp, 0, 0); /* SEEK_SET */
    ssize_t nread = kpm_kernel_read(filp, data, size, &pos);
    filp_close(filp, NULL);

    if (nread != size) {
        klog("kpm_loader: short read on %s: %ld != %lld\n", path, nread, size);
        vfree(data);
        return -1;
    }

    klog("kpm_loader: read %s (%lld bytes), parsing KPM\n", path, size);
    long rc = load_kpm_from_data(data, size, args, "load-file", reserved);
    vfree(data);
    return rc;
}

/* Unload a KPM by name */
static long unload_kpm_name(const char *name, void *reserved)
{
    if (!name) return -1;

    mutex_lock(&kpm_lock);
    struct kpm_module *mod = find_module(name);
    if (!mod) {
        mutex_unlock(&kpm_lock);
        return -2; /* -ENOENT */
    }

    list_del(&mod->list);
    mutex_unlock(&kpm_lock);

    if (mod->exit && *mod->exit) {
        kpm_exitcall_t exit_fn = *mod->exit;
        klog("kpm_loader: calling KPM exit\n");
        call_kpm_exit(exit_fn, reserved);
        klog("kpm_loader: KPM exit returned\n");
    }

    /*
     * Wait for all CPUs to pass a quiescent state before freeing KPM pages.
     * The KPM exit function already unhooks and does IC+TLB broadcast
     * invalidation.  synchronize_rcu ensures any CPU still executing KPM
     * wrapper code has context-switched out, so it won't resume into a
     * now-freed page.
     *
     * We intentionally do NOT use stop_machine for per-CPU ICache drain.
     * kpm_drain_cpu (in this module, NDK-compiled) has a kCFI hash that
     * differs from the kernel compiler's expected hash for int(*)(void*).
     * When the kernel's multi_cpu_stop calls msdata->fn(data), the inline
     * kCFI check fires — and should_cfi_pass only whitelists KPM + thunk
     * areas, not the loader's own .text.  On QEMU with oops=panic this
     * produces a visible panic; on mrdump devices it causes a silent
     * watchdog reset with no pstore record.
     */
    if (cached_synchronize_rcu) {
        klog("kpm_loader: synchronize_rcu before kpm_free_exec\n");
        call_synchronize_rcu();
        klog("kpm_loader: synchronize_rcu done\n");
    }

    klog("kpm_loader: unloading module '%s'\n", mod->info.name);

    if (mod->args) { klog("kpm_loader: vfree args\n"); vfree(mod->args); }
    if (mod->ctl_args) { klog("kpm_loader: vfree ctl_args\n"); vfree(mod->ctl_args); }
    if (mod->got_base) { klog("kpm_loader: free got_base\n"); kpm_free_exec(mod->got_base); }
    klog("kpm_loader: free mod->start = %px\n", mod->start);
    kpm_free_exec(mod->start);
    klog("kpm_loader: vfree mod\n");
    vfree(mod);

    return 0;
}

static long unload_all_kpms(void *reserved)
{
    struct kpm_module *mod;
    struct list_head *pos, *n;
    long count = 0;

    mutex_lock(&kpm_lock);
    for (pos = kpm_modules.next; pos != &kpm_modules; pos = n) {
        n = pos->next;
        mod = list_entry(pos, struct kpm_module, list);
        list_del(&mod->list);

        if (mod->exit && *mod->exit) {
            kpm_exitcall_t exit_fn = *mod->exit;
            call_kpm_exit(exit_fn, reserved);
        }

        klog("kpm_loader: unloading module '%s'\n", mod->info.name);

        if (mod->args) vfree(mod->args);
        if (mod->ctl_args) vfree(mod->ctl_args);
        if (mod->got_base) kpm_free_exec(mod->got_base);
        kpm_free_exec(mod->start);
        vfree(mod);
        count++;
    }
    mutex_unlock(&kpm_lock);

    return count;
}

/* =========================================================================
 * Section 8: ARM64 inline hook engine
 *
 * Based on KernelPatch kernel/base/hook.c
 * ========================================================================= */

#define ARM64_NOP      0xd503201f
#define ARM64_BTI_C    0xd503245f
#define ARM64_BTI_J    0xd503249f
#define ARM64_BTI_JC   0xd50324df
#define ARM64_PACIASP  0xd503233f
#define ARM64_PACIBSP  0xd503237f
/* SCS (Shadow Call Stack): X18 holds shadow stack pointer */
#define ARM64_SCS_PUSH 0xf800845e  /* str x30, [x18], #8  */
#define ARM64_SCS_POP  0xf85f8e5e  /* ldr x30, [x18, #-8]! */

/* PAC stripping: kernel VAs use bits 63..56=0xFF; PAC bits in 54..48.
 * Arithmetic shift (<<8 then >>8) sign-extends bit 55, preserving
 * the kernel VA prefix while clearing PAC signature bits. */
#define STRIP_PAC(ptr) ((void *)(((long)(ptr) << 8) >> 8))

#define TRAMPOLINE_MAX   6
#define RELOCATE_MAX     (4 * 8 + 4)
#define HOOK_REGION_SLOTS 32

/* PC-relative instruction types */
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
/* MASK_IGNORE matches HINT instructions (including PACIA/PACIB/SCS/BTI) */
#define MASK_IGNORE     0xFFFFF01F

typedef struct {
    u64 func_addr;
    u64 origin_addr;
    u64 replace_addr;
    u64 relo_addr;
    s32 tramp_insts_num;
    s32 relo_insts_num;
    u32 origin_insts[TRAMPOLINE_MAX];
    u32 tramp_insts[TRAMPOLINE_MAX];
    /* Executable trampoline — allocated via module_alloc+set_memory_x
     * so the backup is callable on kernels with CONFIG_STRICT_MODULE_RWX. */
    u32 *relo_insts;
    void *relo_alloc;
    unsigned long relo_alloc_size;
    int relo_in_kpm;    /* relo_alloc is within KPM text page (skip vfree/set_memory_x) */
} hook_t;

typedef struct hook_mem_slot {
    int used;
    hook_t hook;
} hook_mem_slot_t;

static hook_mem_slot_t hook_slots[HOOK_REGION_SLOTS];

#define bits32(n, high, low) ((u32)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define sign64_extend(n, len) \
    (((u64)((u64)(n) << (63u - ((len) - 1))) >> 63u) ? ((u64)(n) | (0xFFFFFFFFFFFFFFFFULL << (len))) : (u64)(n))

/* instruction masks and types for classification */
static const u32 hook_masks[] = {
    MASK_B, MASK_BC, MASK_BL, MASK_ADR, MASK_ADRP,
    MASK_LDR_32, MASK_LDR_64, MASK_LDRSW, MASK_PRFM,
    MASK_LDR_SIMD32, MASK_LDR_SIMD64, MASK_LDR_SIMD128,
    MASK_CBZ, MASK_CBNZ, MASK_TBZ, MASK_TBNZ,
    MASK_IGNORE,  /* HINT: PACIA/PACIB/SCS/BTI/NOP */
    0 /* catch-all IGNORE */
};
static const u32 hook_types[] = {
    INST_B, INST_BC, INST_BL, INST_ADR, INST_ADRP,
    INST_LDR_32, INST_LDR_64, INST_LDRSW, INST_PRFM,
    INST_LDR_SIMD32, INST_LDR_SIMD64, INST_LDR_SIMD128,
    INST_CBZ, INST_CBNZ, INST_TBZ, INST_TBNZ,
    INST_IGNORE,
    INST_IGNORE
};
static const s32 relo_lens[] = { 6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2, 2 };

/* Follow branch chains to find the actual code entry */
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

/* Check if an address falls within the trampoline region */
static int is_in_tramp(hook_t *hook, u64 addr)
{
    u64 start = hook->origin_addr;
    u64 end = start + hook->tramp_insts_num * 4;
    return addr >= start && addr < end;
}

/* Convert an address within the trampoline to the relocated address */
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

/* Generate absolute jump: LDR X17, #8; BR X17; .quad target (4 instructions) */
static s32 branch_absolute(u32 *buf, u64 addr)
{
    buf[0] = 0x58000051;   /* LDR X17, #8 */
    buf[1] = 0xD61F0220;   /* BR X17 */
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}

/* Generate jump from src to dst */
static s32 branch_from_to(u32 *buf, u64 src, u64 dst)
{
    (void)src;
    return branch_absolute(buf, dst);
}

/* Relocate a PC-relative branch (B/BC/BL) instruction */
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
        buf[idx++] = (inst & 0xFF00001F) | 0x40u;  /* B.<cond> #8 */
        buf[idx++] = 0x14000006;                     /* B #24 */
    }
    buf[idx++] = 0x58000051;  /* LDR X17, #8 */
    buf[idx++] = 0x14000003;  /* B #12 */
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E;  /* ADR X30, . */
        buf[idx++] = 0x910033DE;  /* ADD X30, X30, #12 */
        buf[idx++] = 0xD65F0220;  /* RET X17 */
    } else {
        buf[idx++] = 0xD65F0220;  /* BR X17 */
    }
    buf[idx++] = ARM64_NOP;
    return 0;
}

/* Relocate ADR/ADRP instructions */
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

    buf[0] = 0x58000040u | xd;  /* LDR Xd, #8 */
    buf[1] = 0x14000003;         /* B #12 */
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 0;
}

/* Relocate LDR literal (and SIMD/FP variants) */
static int relo_ldr(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u32 rt = bits32(inst, 4, 0);
    u64 offset = sign64_extend(bits32(inst, 23, 5) << 2u, 21u);
    u64 addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM) return -1;
    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW) {
        buf[0] = 0x58000060u | rt;  /* LDR Xt, #12 */
        if (type == INST_LDR_32)
            buf[1] = 0xB9400000 | rt | (rt << 5u);   /* LDR Wt, [Xt] */
        else if (type == INST_LDR_64)
            buf[1] = 0xF9400000 | rt | (rt << 5u);   /* LDR Xt, [Xt] */
        else
            buf[1] = 0xB9800000 | rt | (rt << 5u);   /* LDRSW Xt, [Xt] */
        buf[2] = 0x14000004;  /* B #16 */
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        /* SIMD/FP/PRFM — save/restore X16,X17 */
        buf[0] = 0xA93F47F0;  /* STP X16, X17, [SP, -0x10] */
        buf[1] = 0x58000091;  /* LDR X17, #16 */
        if (type == INST_PRFM)
            buf[2] = 0xF9800220 | rt;   /* PRFM */
        else if (type == INST_LDR_SIMD32)
            buf[2] = 0xBD400220 | rt;   /* LDR Sd, [X17] */
        else if (type == INST_LDR_SIMD64)
            buf[2] = 0xFD400220 | rt;   /* LDR Dd, [X17] */
        else
            buf[2] = 0x3DC00220u | rt;  /* LDR Qd, [X17] */
        buf[3] = 0xF85F83F1;  /* LDR X17, [SP, -0x8] now */
        buf[4] = 0x14000004;  /* B #16 */
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return 0;
}

/* Relocate CBZ/CBNZ */
static int relo_cb(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    (void)type;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u64 addr = inst_addr + sign64_extend(bits32(inst, 23, 5) << 2u, 21u);
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u;  /* CB(N)Z Rt, #8 */
    buf[1] = 0x14000005;                     /* B #20 */
    buf[2] = 0x58000051;                     /* LDR X17, #8 */
    buf[3] = 0xD65F0220;                     /* RET X17 */
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return 0;
}

/* Relocate TBZ/TBNZ */
static int relo_tb(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    (void)type;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    u64 addr = inst_addr + sign64_extend(bits32(inst, 18, 5) << 2u, 16u);
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u;  /* TB(N)Z Rt, #<imm>, #8 */
    buf[1] = 0x14000005;
    buf[2] = 0x58000051;
    buf[3] = 0xD61F0220;  /* BR X17 (not RET — tbz uses X17 as scratch) */
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return 0;
}

/* Relocate non-PC-relative instruction (just copy it) */
static int relo_ignore(hook_t *hook, u64 inst_addr, u32 inst, u32 type)
{
    (void)hook; (void)inst_addr; (void)type;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return 0;
}

/* Classify and relocate a single instruction */
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

/* ARM64 hardware-fixed PTE attribute bits — needed early by patch_insn */
#define PTE_RDONLY      (1UL << 7)
#define PTE_DBM         (1UL << 51)

static int pgtable_ready = 0;

/* Forward declarations — PTE manipulation functions (defined later) */
static void pgtable_lazy_init(void);
static u64 *walk_kernel_pte(u64 va);
static void flush_tlb_kernel_page(u64 va);

/* Data passed to stop_machine callback for safe instruction patching */
struct patch_insn_data {
    void *addr;
    u32 insn;
};

static void hook_install(hook_t *hook);

/* Flag set by hook_install_stop_cb to tell patch_insn we're inside a
 * stop_machine callback.  patch_insn must skip synchronize_rcu and
 * nested stop_machine calls — both would deadlock. */
static int g_in_stop_machine = 0;

/* stop_machine callback: install hook while all other CPUs are stopped.
 * Eliminates the race window where another CPU enters the origin function
 * between trampoline make-executable and instruction patching.
 * Sets g_in_stop_machine so patch_insn skips synchronize_rcu / nested
 * stop_machine — both would deadlock from this context. */
static int hook_install_stop_cb(void *data)
{
    hook_t *hook = data;
    g_in_stop_machine = 1;
    hook_install(hook);
    g_in_stop_machine = 0;
    return 0;
}

/* stop_machine callback: runs with all other CPUs stopped.
 * Walks kernel page tables, clears PTE_RDONLY, writes instruction,
 * restores PTE, flushes TLB and icache. */
static int patch_insn_stop_cb(void *data)
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

/* Write a single instruction with cache maintenance.
 *
 * When called from stop_machine context (all other CPUs stopped), the
 * caller is responsible for cross-CPU safety and no additional
 * synchronize_rcu / stop_machine nesting is needed.
 *
 * Strategy (ordered by preference):
 * 1. aarch64_insn_patch_text_nosync — core kernel API.  Only flushes
 *    the local CPU's I-cache, so we follow it with a broadcast I-cache
 *    invalidation (ic ialluis) for cross-CPU safety.  synchronize_rcu()
 *    is used when available to quiesce other CPUs before the flush.
 *    If we're already in atomic context (stop_machine), synchronize_rcu
 *    is skipped — other CPUs are already stopped.
 * 2. Direct PTE manipulation — PTE-based fallback when the fixmap API
 *    is unavailable.  Prefers stop_machine (all CPUs quiesced) when
 *    available, otherwise falls back to IRQ masking on the local CPU.
 *    If already in atomic context, skips nested stop_machine.
 * 3. set_memory_rw + direct write + set_memory_x (vmalloc-backed KPM code)
 * 4. Direct write (for already-writable pages) */
static void patch_insn(void *addr, u32 insn)
{
    /* Tier 1: aarch64_insn_patch_text_nosync — core kernel instruction
     * patching API.  It writes the instruction and flushes the local
     * CPU's I-cache via the fixmap mapping.  However, other CPUs may
     * still have the old instruction in their I-cache, creating a race
     * window on hot paths like __cfi_slowpath (called from arbitrary
     * contexts on all CPUs).
     *
     * Cross-CPU fix-up after the write:
     *   - synchronize_rcu() ensures all CPUs have passed a context
     *     switch, so none are mid-execution inside the patched range.
     *   - "ic ialluis" broadcasts I-cache invalidation to all inner-
     *     shareable CPUs, nuking any stale cached instructions.
     *
     * When in stop_machine context (g_in_stop_machine): skip
     * synchronize_rcu — all other CPUs are already stopped.  Broadcast
     * I-cache flush still runs to handle stale lines when CPUs resume. */
    if (cached_insn_patch) {
        call_insn_patch(addr, insn);

        if (cached_synchronize_rcu && !g_in_stop_machine)
            call_synchronize_rcu();
        asm volatile("ic ialluis\n\t" "dsb ish\n\t" "isb\n\t" ::: "memory");
        return;
    }

    /* Tier 2: Direct PTE manipulation — bypasses mkp vendor hooks entirely.
     * Prefer stop_machine (all CPUs quiesced) when available, otherwise
     * fall back to IRQ masking on the local CPU.
     * When already in stop_machine, skip nested stop_machine and do the
     * direct write — the outer stop_machine already ensures quiescence. */
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

    /* Tier 3: set_memory_rw→write→set_memory_x (vmalloc-backed KPM code).
     * aarch64_insn_patch_text_nosync BUGs on non-.text addresses on some kernels. */
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

    /* Tier 4: Direct write (already-writable page) */
    *(u32 *)addr = insn;
    if (cached_flush_icache)
        call_flush_icache((unsigned long)addr, (unsigned long)addr + 4);
}

/* Allocate a hook slot */
static hook_t *hook_alloc(u64 origin_addr)
{
#define TRAMP_SPACE 512  /* bytes needed per trampoline (with CFI prefix) */
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (!hook_slots[i].used) {
            size_t exec_size;
            void *exec_mem = NULL;
            int in_kpm = 0;

            /* Prefer KPM text page tail — already executable, avoids
             * set_memory_x failures on separate vmalloc pages (5.10). */
            struct kpm_module *mod;
            mutex_lock(&kpm_lock);
            mod = find_module_by_text_addr(origin_addr);
            if (mod && (mod->text_size - mod->text_used) >= TRAMP_SPACE) {
                exec_mem = (char *)mod->start + mod->text_used;
                exec_size = TRAMP_SPACE;
                mod->text_used += TRAMP_SPACE;
                in_kpm = 1;
                memset(exec_mem, 0, exec_size);
            }
            mutex_unlock(&kpm_lock);

            if (!exec_mem) {
                exec_size = PAGE_SIZE;
                exec_mem = vmalloc(exec_size);
                if (!exec_mem) return NULL;
                memset(exec_mem, 0, exec_size);
            }

            hook_slots[i].used = 1;
            memset(&hook_slots[i].hook, 0, sizeof(hook_t));
            hook_slots[i].hook.origin_addr = origin_addr;
            hook_slots[i].hook.relo_in_kpm = in_kpm;
            /* relo_insts[0] at offset +4; offset -4..0 reserved for CFI hash */
            hook_slots[i].hook.relo_insts = (u32 *)((char *)exec_mem + 4);
            hook_slots[i].hook.relo_alloc = exec_mem;
            hook_slots[i].hook.relo_alloc_size = exec_size;
            return &hook_slots[i].hook;
        }
    }
    return NULL;
#undef TRAMP_SPACE
}

/* Find an existing hook by origin address */
static hook_t *hook_find(u64 origin_addr)
{
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (hook_slots[i].used && hook_slots[i].hook.origin_addr == origin_addr)
            return &hook_slots[i].hook;
    }
    return NULL;
}

/* Free a hook slot */
static void hook_free(hook_t *hook)
{
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (&hook_slots[i].hook == hook) {
            if (hook->relo_alloc && !hook->relo_in_kpm)
                vfree(hook->relo_alloc);
            hook_slots[i].used = 0;
            return;
        }
    }
}

/* Prepare a hook: backup original instructions, generate trampoline, relocate */
static int hook_prepare(hook_t *hook)
{
    /* Backup original instructions */
    for (int i = 0; i < TRAMPOLINE_MAX; i++)
        hook->origin_insts[i] = *((u32 *)hook->origin_addr + i);

    /* Handle BTI, PAC, or BTI+PAC at function entry.
     * Order matters: BTI first (landing pad), then PAC (sign return) */
    u32 first = hook->origin_insts[0];
    int is_bti = (first == ARM64_BTI_C || first == ARM64_BTI_J || first == ARM64_BTI_JC);
    int is_pac = (first == ARM64_PACIASP || first == ARM64_PACIBSP);

    if (is_bti || is_pac) {
        /* 5-instruction trampoline:
         * tramp[0] = BTI_JC (preserves landing pad at hooked function entry)
         * tramp[1..4] = branch_absolute to replace_addr */
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num = 1 + branch_from_to(&hook->tramp_insts[1],
                                                    hook->origin_addr, hook->replace_addr);
    } else {
        /* Standard 4-instruction trampoline */
        hook->tramp_insts_num = branch_from_to(hook->tramp_insts,
                                               hook->origin_addr, hook->replace_addr);
    }

    /* Clear relocation area */
    for (int i = 0; i < RELOCATE_MAX; i++)
        hook->relo_insts[i] = ARM64_NOP;

    /* BTI landing pad in relocated code */
    hook->relo_insts[0] = ARM64_BTI_JC;
    hook->relo_insts[1] = ARM64_NOP;
    hook->relo_insts_num = 2;

    /* Relocate each original instruction */
    for (int i = 0; i < hook->tramp_insts_num; i++) {
        u64 inst_addr = hook->origin_addr + i * 4;
        u32 inst = hook->origin_insts[i];
        if (relocate_inst(hook, inst_addr, inst) < 0)
            return -1;
    }

    /* Jump back from relocated code to instruction after trampoline */
    u64 back_src = hook->relo_addr + hook->relo_insts_num * 4;
    u64 back_dst = hook->origin_addr + hook->tramp_insts_num * 4;
    u32 *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src, back_dst);

    /* Copy kCFI type hash from original function to relocated code prefix.
     * kCFI validates *(target - 4) before every indirect call; placing the
     * original function's hash at relo_insts[-1] allows the backup pointer
     * returned by do_hook() to pass CFI validation. On non-kCFI kernels
     * the memory at origin_addr-4 may not be readable, so we check first.
     * Also reject page-aligned addresses: vmalloc guard pages sit between
     * allocations, and *(page_start-4) faults with a translation fault. */
    if (hook->origin_addr > 4 && (hook->origin_addr & 0xFFF) >= 4) {
        u32 cfi_hash = *(u32 *)(hook->origin_addr - 4);
        /* Only copy if it looks like a valid CFI hash (upper 2 bits are type tag) */
        if (cfi_hash && cfi_hash != 0xFFFFFFFF)
            *(u32 *)((u8 *)hook->relo_insts - 4) = cfi_hash;
    }

    /* Make trampoline executable and flush I-cache.
     * Skip set_memory_x when in KPM text page (already executable).
     * I-cache flush is always needed — D-cache and I-cache are not coherent. */
    if (hook->relo_in_kpm) {
        klog("kpm_loader: trampoline in KPM text page %px (skip set_memory_x)\n",
             hook->relo_alloc);
    } else if (cached_set_memory_x && hook->relo_alloc) {
        int np = (int)((hook->relo_alloc_size + PAGE_SIZE - 1) / PAGE_SIZE);
        klog("kpm_loader: set_memory_x trampoline(%px, %d) calling...\n",
             hook->relo_alloc, np);
        int rc = call_set_memory_x((unsigned long)hook->relo_alloc, np);
        klog("kpm_loader: set_memory_x trampoline returned %d\n", rc);
    } else {
        klog("kpm_loader: set_memory_x trampoline SKIP sx=%d ra=%px\n",
             !!cached_set_memory_x, hook->relo_alloc);
    }
    if (cached_flush_icache && hook->relo_alloc) {
        call_flush_icache((unsigned long)hook->relo_alloc,
                          (unsigned long)hook->relo_alloc + hook->relo_alloc_size);
    }

    return 0;
}

/* Install hook: write trampoline to target function.  Called either
 * directly or via stop_machine for cross-CPU safety. */
static void hook_install(hook_t *hook)
{
    for (int i = 0; i < hook->tramp_insts_num; i++) {
        u32 *addr = (u32 *)hook->origin_addr + i;
        patch_insn(addr, hook->tramp_insts[i]);
    }
}

/* Uninstall hook: restore original instructions */
static void hook_uninstall(hook_t *hook)
{
    for (int i = 0; i < hook->tramp_insts_num; i++) {
        u32 *addr = (u32 *)hook->origin_addr + i;
        patch_insn(addr, hook->origin_insts[i]);
    }
}

/* One-shot inline hook */
static long do_hook(void *func, void *replace, void **backup)
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

    /* Use stop_machine to atomically patch the origin — prevents the race
     * where another CPU enters the origin between trampoline set_memory_x
     * and instruction patching, hitting an inconsistent state. */
    if (cached_stop_machine)
        call_stop_machine(hook_install_stop_cb, hook);
    else
        hook_install(hook);
    *backup = STRIP_PAC((void *)hook->relo_addr);

    klog("kpm_loader: hooked func %llx -> %llx\n", hook->func_addr, hook->replace_addr);
    return 0;
}

/* One-shot inline unhook */
static void do_unhook(void *func)
{
    if (!func) return;
    func = STRIP_PAC(func);

    /*
     * Look up by func directly — NOT by branch_func_addr(func).
     * After hook_install patches the entry point with a branch to the
     * trampoline, branch_func_addr would follow that branch into KPM
     * memory and return a trampoline/KPM address instead of the
     * original function address.  hook->origin_addr was set to
     * branch_func_addr(func) BEFORE patching (in do_hook), which for
     * functions without leading B/BTI equals func itself.  Using func
     * directly is the correct lookup key in the common case.
     */
    hook_t *hook = hook_find((u64)func);
    if (!hook) {
        u64 bfa = branch_func_addr((u64)func);
        klog("kpm_loader: do_unhook(%px) direct lookup failed, "
             "branch_func_addr=%llx, trying fallback\n", func, bfa);
        /* Fallback for functions that originally started with B/BTI */
        hook = hook_find(bfa);
    }
    if (!hook) {
        klog("kpm_loader: do_unhook(%px) hook not found (neither direct nor fallback)\n",
             func);
        return;
    }

    hook_uninstall(hook);
    hook_free(hook);
    klog("kpm_loader: unhooked func %llx\n", (u64)func);
}

/* =========================================================================
 * Section 8b: KernelPatch API compatibility layer
 *
 * Provides hook_wrap / unhook / fp_wrap_syscalln / inline_wrap_syscalln /
 * compat_strncpy_from_user / kallsyms_lookup_name — the symbols that
 * official KernelPatch KPM demos (demo-inlinehook, demo-syscallhook)
 * reference as undefined.
 *
 * Architecture: thunk-based trampolines
 *   Each hook_wrap call allocates a 32-byte thunk from a static pool.
 *   The thunk loads a chain pointer (into x9) and a dispatch address
 *   (into x16), then branches to the shared C dispatch function.
 *   The dispatch function builds a hook_fargs8_t on the stack, then
 *   calls before → backup → after in sequence.
 *
 * Compatibility with wrap_get_origin_func / fp_get_origin_func:
 *   The chain struct mimics hook_chain_t layout so that offset 24
 *   (hook.relo_addr) holds the backup (relocated original) address.
 * ========================================================================= */

#define KP_CHAIN_NUM    8
#define KP_THUNK_SIZE   32
#define KP_THUNK_POOL   (KP_CHAIN_NUM * KP_THUNK_SIZE)

/* Chain struct — offset 24 holds backup for wrap_get_origin_func compat */
typedef struct {
    u64 _pad0;          /* +0  (hook.func_addr) */
    u64 _pad1;          /* +8  (hook.origin_addr) */
    u64 _pad2;          /* +16 (hook.replace_addr) */
    u64 backup;         /* +24 (hook.relo_addr) ← wrap_get_origin_func reads */
    void *before;       /* +32 */
    void *after;        /* +40 */
    void *udata;        /* +48 */
    int argno;          /* +56 */
    int occupied;       /* +60 */
    u32 *thunk;         /* +64 pointer to the allocated executable thunk */
    void *original_func; /* +72 the hooked function address */
    u32 cfi_hash;       /* +80 kCFI type hash copied from original func-4 */
} kp_chain_t;

/* Thunk template (32 bytes, module_alloc + set_memory_x):
 *   ldr x9,  #16    ; load chain ptr from inline data
 *   ldr x16, #20    ; load dispatch addr from inline data
 *   br  x16         ; jump to shared dispatch
 *   nop             ; alignment
 *   .quad chain_ptr   (bytes 16–23, replaced at alloc time)
 *   .quad dispatch    (bytes 24–31, replaced at alloc time) */
static const u32 kp_thunk_tmpl[8] = {
    0x58000089,  /* ldr x9, #16  (imm19=4, Rt=9) */
    0x580000B0,  /* ldr x16, #20 (imm19=5, Rt=16) */
    0xD61F0200,  /* br x16 */
    0xD503201F,  /* nop */
    0, 0,        /* chain ptr placeholder (u64) */
    0, 0,        /* dispatch addr placeholder (u64) */
};

static kp_chain_t kp_chains[KP_CHAIN_NUM];
/* Each thunk is allocated via module_alloc/vmalloc and made executable.
 * kp_thunk_addrs[i] tracks the allocated address for freeing. */
static u32 *kp_thunk_addrs[KP_CHAIN_NUM];

static bool is_thunk_area(unsigned long addr)
{
    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (!kp_thunk_addrs[i])
            continue;
        unsigned long start = (unsigned long)kp_thunk_addrs[i] & ~(PAGE_SIZE - 1);
        unsigned long end = start + PAGE_SIZE;
        if (addr >= start && addr < end)
            return true;
    }
    return false;
}

static bool should_cfi_pass(unsigned long target)
{
    return is_kpm_area(target) || is_thunk_area(target);
}

/* Syscall hook globals (kp_has_syscall_wrapper declared in .data above) */
static unsigned long kp_sys_call_table = 0;

/* Forward declare the dispatch function */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi"), noinline))
static u64 kp_dispatch_main(u64 a0, u64 a1, u64 a2, u64 a3,
                            u64 a4, u64 a5, u64 a6, u64 a7);

/* Allocate an executable thunk via vmalloc + set_memory_x.
 * Returns chain slot index, or -1 if pool is full or alloc fails. */
static int kp_thunk_alloc(kp_chain_t *chain)
{
    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (!kp_thunk_addrs[i]) {
            void *mem = NULL;
            /* Prefer vmalloc — set_memory_x silently fails on module_alloc
             * on some 5.10 kernels. */
            if (false && cached_module_alloc)
                mem = call_module_alloc(PAGE_SIZE);
            else
                mem = vmalloc(PAGE_SIZE);
            if (!mem) return -1;
            __builtin_memset(mem, 0, PAGE_SIZE);

            /* Place thunk at mem+8 so kCFI hash at mem+4 (= thunk-4)
             * is within the same vmalloc page (not the guard page).
             * Layout: mem[0..3]=unused, mem[4..7]=cfi_hash, mem[8..40]=thunk */
            u32 *thunk = (u32 *)((u8 *)mem + 8);
            *(u32 *)(thunk - 1) = chain->cfi_hash;
            __builtin_memcpy(thunk, kp_thunk_tmpl, KP_THUNK_SIZE);
            /* Patch inline data: chain ptr at thunk+16, dispatch at thunk+24 */
            *(u64 *)(thunk + 4) = (u64)chain;
            *(u64 *)(thunk + 6) = (u64)&kp_dispatch_main;

            /* Make thunk executable */
            if (cached_set_memory_x) {
                int rc = call_set_memory_x((unsigned long)mem, 1);
                if (rc) {
                    klog("kpm_loader: set_memory_x thunk failed: %d\n", rc);
                    vfree(mem);
                    return -1;
                }
            }
            /* Flush icache for the newly written instructions when available. */
            if (cached_flush_icache) {
                call_flush_icache((unsigned long)thunk,
                                (unsigned long)thunk + KP_THUNK_SIZE);
            }

            kp_thunk_addrs[i] = thunk;
            chain->thunk = thunk;
            return i;
        }
    }
    return -1;
}

static void kp_thunk_free(int idx)
{
    if (idx >= 0 && idx < KP_CHAIN_NUM && kp_thunk_addrs[idx]) {
        void *page = (void *)((unsigned long)kp_thunk_addrs[idx] & ~(PAGE_SIZE - 1));
        vfree(page);
        kp_thunk_addrs[idx] = 0;
    }
    if (idx >= 0 && idx < KP_CHAIN_NUM) {
        kp_chains[idx].thunk = 0;
        kp_chains[idx].occupied = 0;
    }
}

/* Shared dispatch: called via thunk br x16 with chain ptr in x9.
 * Parameters a0–a7 are the original function's arguments (x0–x7).
 * Builds hook_fargs8_t on the stack and calls before → backup → after.
 *
 * The hook_fargs_t layout (KernelPatch compatible):
 *   +0:  chain ptr (void *)
 *   +8:  skip_origin (int32_t) + 4 bytes padding
 *   +16: local (8 × u64 = 64 bytes)
 *   +80: ret (u64)
 *   +88: args[] (u64 per arg)
 *
 * Total for 8 args: 8 + 8 + 64 + 8 + 64 = 152 bytes */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi"), noinline))
static u64 kp_dispatch_main(u64 a0, u64 a1, u64 a2, u64 a3,
                            u64 a4, u64 a5, u64 a6, u64 a7)
{
    kp_chain_t *chain;
    asm volatile("mov %0, x9" : "=r"(chain));
    if (!chain || !chain->occupied) return 0;

    /* Build fargs on stack */
    u8 fargs_buf[160] __attribute__((aligned(8)));
    u64 *fargs_ptr = (u64 *)fargs_buf;
    for (int _i = 0; _i < 20; _i++)
        ((volatile unsigned long *)fargs_buf)[_i] = 0;

    fargs_ptr[0] = (u64)chain;     /* chain */
    fargs_ptr[2] = 0;              /* local.data0..7 already zeroed */
    fargs_ptr[10] = (u64)a0;       /* ret (placeholder, overwritten later) */
    fargs_ptr[11] = (u64)a0;       /* args[0] */
    fargs_ptr[12] = (u64)a1;       /* args[1] */
    fargs_ptr[13] = (u64)a2;       /* args[2] */
    fargs_ptr[14] = (u64)a3;       /* args[3] */
    fargs_ptr[15] = (u64)a4;       /* args[4] */
    fargs_ptr[16] = (u64)a5;       /* args[5] */
    fargs_ptr[17] = (u64)a6;       /* args[6] */
    fargs_ptr[18] = (u64)a7;       /* args[7] */

    void *fargs = (void *)fargs_buf;

    /* Call before callback */
    if (chain->before) {
        typedef void (*before_fn)(void *, void *);
        ((before_fn)chain->before)(fargs, chain->udata);
    }

    /* Call backup (relocated original) with original arguments.
     * Use inline asm to ensure args are in the right registers. */
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
            : "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
              "x16", "x17", "x30", "memory"
        );
        ret = r0;
    }

    /* Store return value in fargs.ret */
    ((u64 *)fargs_ptr)[10] = ret;

    /* Call after callback */
    if (chain->after) {
        typedef void (*after_fn)(void *, void *);
        ((after_fn)chain->after)(fargs, chain->udata);
    }

    /* Return final ret value (may have been modified by after callback) */
    return ((u64 *)fargs_ptr)[10];
}

/* ---- hook_wrap / unhook implementations ---- */

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long kp_hook_wrap(void *func, int argno, void *before,
                         void *after, void *udata)
{
    if (!func) return -4095; /* HOOK_BAD_ADDRESS */

    func = STRIP_PAC(func);

    /* Check if already hooked */
    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (kp_chains[i].occupied && kp_chains[i].original_func == func) {
            /* Chain already exists for this function — add to it.
             * For simplicity (single before/after like the demos), replace. */
            kp_chains[i].before = before;
            kp_chains[i].after  = after;
            kp_chains[i].udata  = udata;
            kp_chains[i].argno  = argno;
            return 0; /* HOOK_NO_ERR */
        }
    }

    /* Allocate chain slot */
    int slot = -1;
    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (!kp_chains[i].occupied) { slot = i; break; }
    }
    if (slot < 0) return -4093; /* HOOK_NO_MEM */

    kp_chain_t *chain = &kp_chains[slot];
    __builtin_memset(chain, 0, sizeof(*chain));
    chain->before = before;
    chain->after  = after;
    chain->udata  = udata;
    chain->argno  = argno;
    chain->original_func = func;

    /* Allocate the thunk (executable trampoline) */
    int tidx = kp_thunk_alloc(chain);
    if (tidx < 0) return -4093; /* HOOK_NO_MEM */

    /* Install inline hook: func -> thunk, backup = relocated original */
    void *backup = 0;
    long err = do_hook(func, (void *)chain->thunk, &backup);
    if (err) {
        kp_thunk_free(tidx);
        return -4092; /* HOOK_BAD_RELO */
    }
    chain->backup = (u64)STRIP_PAC(backup);
    chain->occupied = 1;

    return 0; /* HOOK_NO_ERR */
}

static void kp_unhook(void *func)
{
    if (!func) return;
    func = STRIP_PAC(func);

    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (kp_chains[i].occupied && kp_chains[i].original_func == func) {
            do_unhook(func);
            kp_thunk_free(i);
            return;
        }
    }
    /* Fallback: try one-shot unhook (for non-chain hooks) */
    do_unhook(func);
}

/* hook_unwrap_remove — KP chain-based unhook with remove flag.
 * In the full KernelPatch, this removes a specific (before,after) pair from
 * the hook chain and only uninstalls the hook when all pairs are gone.
 * For our simplified compat layer, we fully unhook when remove=1
 * (which is what hook_unwrap() calls). */
static void kp_hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    (void)before;
    (void)after;
    if (remove && func) kp_unhook(func);
}

/* ---- compat_strncpy_from_user ---- *
 * Reads at most count-1 characters from userspace string src into dest,
 * null-terminates. Returns the length of the string (not counting NUL)
 * or -EFAULT on access fault.
 *
 * Uses LDTRB (unprivileged load) to safely read userspace memory.
 * On GKI 5.10, LDTRB triggers a fault handler that calls fixup_exception
 * instead of panicking — the asm goto catches the fault. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long kp_compat_strncpy_from_user(char *dest, const char __user *src, long count)
{
    /* Prefer the kernel's own strncpy_from_user (handles PAN, KPTI,
     * exception tables, etc. correctly on all kernel versions). */
    if (cached_strncpy_from_user) {
        typedef long (*fn_t)(char *d, const char __user *s, long n);
        return ((fn_t)cached_strncpy_from_user)(dest, src, count);
    }

    /* Fallback: if kernel strncpy_from_user is unavailable,
     * return -1 to signal error to the caller. */
    return -1;
}

/* ---- kallsyms_lookup_name export ---- *
 * Direct wrapper so KPMs can call kallsyms_lookup_name without
 * going through our cached symbol resolution. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long kp_kallsyms_lookup_name(const char *name)
{
    if (!name) return 0;
    /* Try local symbols first (for symbols exported by the loader) */
    unsigned long local = local_sym_lookup(name);
    if (local) return local;
    return kallsyms_lookup(name);
}

/* ---- Direct PTE write for __ro_after_init memory ----
 *
 * sys_call_table and other kernel .data items are marked __ro_after_init.
 * set_memory_rw() only works on vmalloc pages, not kernel .data/.rodata.
 * aarch64_insn_patch_text_nosync() BUGs on non-.text addresses.
 * The only reliable method: walk kernel page tables, clear PTE_RDONLY,
 * write through the original VA, restore PTE, flush TLB.
 * Based on KernelHook Tier 3 (write_insts_via_pte). */

/* ARM64 hardware-fixed PTE attribute bits */
#define PTE_VALID       (1UL << 0)
#define PTE_TYPE_BLOCK  (1UL << 0)
#define PTE_TYPE_TABLE  (3UL << 0)
#define PTE_ADDR_MASK   0x0000FFFFFFFFF000ULL

static u64 page_offset_v = 0;
static u64 phys_offset_v = 0;
static int page_levels = 3;

/* Lazy init: detect VA_BITS from TCR_EL1, compute derived values */
static void pgtable_lazy_init(void)
{
    if (pgtable_ready) return;
    u64 tcr;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    u64 t1sz = (tcr >> 16) & 0x3f;
    u64 va_bits = 64 - t1sz;
    page_offset_v = ~((1ULL << va_bits) - 1);
    /* memstart_addr is a variable — read the value at the resolved address */
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

/* Walk kernel page tables to find the PTE for @va.
 * Returns pointer to PTE (u64*), or NULL on failure. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static u64 *walk_kernel_pte(u64 va)
{
    if (!pgtable_ready) return 0;
    u64 pxd_bits = 9; /* bits per level for 4KB pages */
    u64 pxd_ptrs = 512;

    /* Use swapper_pg_dir if resolved; otherwise read TTBR1_EL1 directly */
    u64 pxd_va = cached_swapper_pg_dir;
    if (!pxd_va) {
        u64 ttbr1;
        asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
        u64 pgd_pa = ttbr1 & ~0xFFFFULL; /* clear ASID/attributes */
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
            if (lv == 3) {
                /* Page descriptor at final level — leaf */
                leaf_entry_va = entry_va;
                break;
            }
            /* Table descriptor — descend to next level */
            u64 pa = desc & PTE_ADDR_MASK;
            pxd_va = __pa_to_va(pa);
        } else if (kind == 0x1) {
            /* Block descriptor at intermediate level — leaf for 2MB/1GB mappings.
             * sys_call_table on 5.10 GKI is often in a PMD block (2MB) mapping. */
            leaf_entry_va = entry_va;
            break;
        } else {
            return 0;
        }
    }
    return (u64 *)leaf_entry_va;
}

/* Flush TLB for a single kernel VA. Architecturally correct sequence. */
static inline void flush_tlb_kernel_page(u64 va)
{
    u64 addr = (va >> 12) & ((1ULL << 44) - 1);
    asm volatile("dsb ishst" ::: "memory");
    asm volatile("tlbi vaale1is, %0" :: "r"(addr) : "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

/* Write a 64-bit value to any kernel address by temporarily clearing
 * PTE_RDONLY on the target page. Safe for __ro_after_init memory. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void write_kernel_u64(u64 *dst, u64 val)
{
    u64 va = (u64)dst;
    u64 *pte = walk_kernel_pte(va);
    if (!pte) {
        *dst = val;  /* fallback: direct write if page is already writable */
        return;
    }

    u64 orig = *pte;
    *pte = (orig | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(va);

    *dst = val;

    *pte = orig;
    flush_tlb_kernel_page(va);
}

/* ---- Syscall hook compat layer ---- */

/* Initialize syscall hook globals. Called from kp_syscall_hook_init()
 * which runs the first time any syscall hook API is invoked. */
static int kp_syscall_hook_init(void)
{
    if (kp_sys_call_table) return 0;

    pgtable_lazy_init();

    kp_sys_call_table = kallsyms_lookup("sys_call_table");
    if (!kp_sys_call_table) {
        klog("kpm_loader: cannot find sys_call_table\n");
        return -1;
    }

    /* has_syscall_wrapper: set to 1 if the kernel wraps syscalls
     * (GKI 5.10+ has CONFIG_ARM64_SYSCALL_WRAPPER=y).
     * Detect by checking if __arm64_sys_openat exists. */
    if (kallsyms_lookup("__arm64_sys_openat"))
        kp_has_syscall_wrapper = 1;

    /* Update the has_syscall_wrapper export */
    local_syms[20].addr = (unsigned long)&kp_has_syscall_wrapper;

    klog("kpm_loader: syscall hook init: sys_call_table=%llx wrapper=%d\n",
           (u64)kp_sys_call_table, kp_has_syscall_wrapper);
    return 0;
}

/* Get the address of syscall number @nr from sys_call_table */
static u64 kp_syscall_addr(int nr)
{
    if (!kp_sys_call_table || nr < 0) return 0;
    /* sys_call_table is an array of function pointers */
    unsigned long *table = (unsigned long *)kp_sys_call_table;
    return (u64)table[nr];
}

/* Function pointer hook on syscall: replace sys_call_table[nr] with
 * a chain transit thunk, preserving the original FP as backup. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long kp_fp_wrap_syscalln(int nr, int narg, int is_compat,
                                void *before, void *after, void *udata)
{
    (void)is_compat;
    if (kp_syscall_hook_init() != 0) return -4095;

    u64 fp_addr = (u64)kp_sys_call_table + (u64)nr * sizeof(unsigned long);
    u64 origin_syscall = kp_syscall_addr(nr);
    if (!origin_syscall) return -4095;

    /* Build chain for the syscall function.
     * The transit passes pt_regs* as args[0] when has_syscall_wrapper=1. */
    kp_chain_t *chain = 0;
    int slot = -1;
    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (!kp_chains[i].occupied) { slot = i; break; }
    }
    if (slot < 0) return -4093;

    chain = &kp_chains[slot];
    __builtin_memset(chain, 0, sizeof(*chain));
    chain->before = before;
    chain->after  = after;
    chain->udata  = udata;
    chain->argno  = narg;
    chain->original_func = (void *)fp_addr; /* marker: this is an FP hook */
    chain->backup  = origin_syscall;        /* original syscall handler */

    /* Copy kCFI type hash from the original syscall handler so the
     * thunk passes CFI checks when called through sys_call_table. */
    if (origin_syscall > 4 && (origin_syscall & 0xFFF) >= 4) {
        chain->cfi_hash = *(u32 *)(origin_syscall - 4);
        klog("kpm_loader: cfi_hash from %llx = %08x\n",
               (u64)origin_syscall, chain->cfi_hash);
    } else {
        klog("kpm_loader: cfi_hash skipped (origin=%llx off=%llx)\n",
               (u64)origin_syscall, origin_syscall & 0xFFF);
    }

    int tidx = kp_thunk_alloc(chain);
    if (tidx < 0) return -4093;

    /* Write 64-bit pointer into sys_call_table[nr] via PTE manipulation.
     * sys_call_table is __ro_after_init; set_memory_rw() and
     * aarch64_insn_patch_text_nosync both fail on it. */
    write_kernel_u64((u64 *)fp_addr, (u64)chain->thunk);
    chain->occupied = 1;

    klog("kpm_loader: fp_hook syscall[%d] %llx -> thunk %px\n",
           nr, (u64)origin_syscall, chain->thunk);
    return 0;
}

/* Remove function pointer hook from syscall table */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void kp_fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    (void)is_compat;
    (void)before;
    (void)after;
    if (!kp_sys_call_table || nr < 0) return;

    u64 fp_addr = (u64)kp_sys_call_table + (u64)nr * sizeof(unsigned long);

    for (int i = 0; i < KP_CHAIN_NUM; i++) {
        if (kp_chains[i].occupied && kp_chains[i].original_func == (void *)fp_addr) {
            /* Restore original syscall handler via PTE manipulation */
            write_kernel_u64((u64 *)fp_addr, kp_chains[i].backup);
            kp_thunk_free(i);
            klog("kpm_loader: fp_unhook syscall[%d] restored %llx\n",
                   nr, (u64)kp_chains[i].backup);
            return;
        }
    }
}

/* Inline hook on syscall handler function */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long kp_inline_wrap_syscalln(int nr, int narg, int is_compat,
                                    void *before, void *after, void *udata)
{
    (void)is_compat;
    if (kp_syscall_hook_init() != 0) return -4095;

    u64 syscall_func = kp_syscall_addr(nr);
    if (!syscall_func) return -4095;

    return kp_hook_wrap((void *)syscall_func, narg, before, after, udata);
}

/* Remove inline hook from syscall handler */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static void kp_inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    (void)is_compat;
    (void)before;
    (void)after;
    if (!kp_sys_call_table || nr < 0) return;

    u64 syscall_func = kp_syscall_addr(nr);
    if (!syscall_func) return;

    kp_unhook((void *)syscall_func);
}

/* =========================================================================
 * Section 9: Loader API table
 * ========================================================================= */

/* Wrapper for the lookup_symbol API: kallsyms_lookup returns &kp_printk_ptr
 * (the address of the function-pointer variable) so that KPM symbol resolution
 * can embed the pointer address into MOV+MOVK+LDR+BLR sequences.  But KPMs
 * that call loader_api.lookup_symbol("printk") expect the callable function
 * address directly.  Dereference here. */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static unsigned long api_lookup_symbol(const char *name)
{
    unsigned long addr = kallsyms_lookup(name);
    if (addr && strcmp(name, "printk") == 0)
        addr = *(unsigned long *)addr;
    return addr;
}

static long api_kpm_control(const char *name, const char *args,
                            char *out_msg, int outlen)
{
    struct kpm_module *mod = find_module(name);
    if (!mod || !mod->ctl0 || !*mod->ctl0) return -1;
    return call_kpm_ctl0(*mod->ctl0, args, out_msg, outlen);
}

static struct kpm_api loader_api = {
    .lookup_symbol = (void *)api_lookup_symbol,
    .load_kpm      = (void *)load_kpm_file,
    .unload_kpm    = (void *)unload_kpm_name,
    .hook          = (void *)do_hook,
    .unhook        = (void *)do_unhook,
    .printk        = 0, /* set at init after resolve_printk() */
};

/* =========================================================================
 * Section 10: Custom syscall interface (replaces /proc/kpm_loader)
 *
 * On 6.x kCFI kernels, /proc/kpm_loader triggers inline kCFI type-hash checks
 * at proc_reg_read → ops->proc_read.  The kernel and NDK use different clang
 * versions with different kCFI hash algorithms for complex parameter types
 * (struct file *, char __user *, size_t, loff_t *), so the hashes mismatch
 * and even when they match the kernel may clobber the function-pointer register.
 *
 * Syscall dispatch (arch/arm64/kernel/entry.S) uses raw `blr x16` — no kCFI
 * inline check — so a stolen syscall slot avoids the problem entirely.
 *
 * Userspace:  syscall(KPM_SYSCALL_NR, cmd, arg1, arg2, arg3)
 *
 * Commands:
 *   LOAD   (0)  arg1=path, arg2=args
 *   UNLOAD (1)  arg1=name ("" = unload all)
 *   LIST   (2)  arg1=out_buf, arg2=out_size → bytes written
 *   KADDR  (3)  arg1=hex_addr (0 = read current)
 *   CTL    (4)  arg1=name_str, arg2=args_str, arg3=out_buf/out_size
 *   BYPASS (5)  no args
 *   HOOK_TEST   (6)  no args
 *   UNHOOK_TEST (7)  no args
 * ========================================================================= */

#define KPM_SYSCALL_NR    448
#define KPM_CMD_LOAD      0
#define KPM_CMD_UNLOAD    1
#define KPM_CMD_LIST      2
#define KPM_CMD_KADDR     3
#define KPM_CMD_CTL       4
#define KPM_CMD_BYPASS    5
#define KPM_CMD_HOOK_TEST 6
#define KPM_CMD_UNHOOK_TEST 7

/* Original entry (restored at exit) and resolved syscall number */
static unsigned long kpm_syscall_original = 0;
static unsigned long kpm_syscall_nr = 0;

/* Buffer for LIST/status output */
static char kpm_syscall_buf[4096];

/* kCFI type-hash prefix for kpm_syscall_handler on wrapper kernels.
 * On 6.x the invoke_syscall() C code does an inline ldr w16,[x16,#-4] check
 * so the 4 bytes immediately before the handler must match the expected hash.
 * Declared const so the section stays read-only in ELF (6.x rejects WRITE|EXEC
 * in .text). The real hash is patched at register time via PTE write. */
__attribute__((used, section(".kcfi_prefix.kpm_syscall_handler")))
static const unsigned long kpm_handler_cfi_prefix = 0;

/* Extract the real command and user arguments from the syscall frame.
 * On wrapper kernels the handler sees (pt_regs *) in x0; on non-wrapper
 * kernels the user arguments are in x0..x5 directly. */
static int kpm_syscall_extract_cmd(unsigned long a0, unsigned long a1,
                                    unsigned long a2, unsigned long a3,
                                    void **arg1, void **arg2, void **arg3_out)
{
    int cmd;
    if (kp_has_syscall_wrapper) {
        unsigned long *regs = (unsigned long *)a0;
        cmd       = (int)regs[0];
        *arg1     = (void *)regs[1];
        *arg2     = (void *)regs[2];
        *arg3_out = (void *)regs[3];
    } else {
        cmd       = (int)a0;
        *arg1     = (void *)a1;
        *arg2     = (void *)a2;
        *arg3_out = (void *)a3;
    }
    return cmd;
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi"),
               section(".text.kpm_syscall_handler")))
static long kpm_syscall_handler(unsigned long a0, unsigned long a1,
                                 unsigned long a2, unsigned long a3)
{
    void *arg1, *arg2, *arg3;
    int cmd = kpm_syscall_extract_cmd(a0, a1, a2, a3, &arg1, &arg2, &arg3);

    switch (cmd) {

    case KPM_CMD_LOAD: {
        char path[256];
        char args[256];
        long r = kp_compat_strncpy_from_user(path,
                (const char __user *)arg1, sizeof(path));
        if (r < 0) return -14;
        if (arg2) {
            r = kp_compat_strncpy_from_user(args,
                    (const char __user *)arg2, sizeof(args));
            if (r < 0) return -14;
        } else {
            args[0] = 0;
        }
        return load_kpm_file(path, args[0] ? args : NULL, &loader_api);
    }

    case KPM_CMD_UNLOAD: {
        char name[128];
        long r = kp_compat_strncpy_from_user(name,
                (const char __user *)arg1, sizeof(name));
        if (r < 0) return -14;
        if (name[0] == 0) {
            unload_all_kpms(NULL);
            return 0;
        }
        return unload_kpm_name(name, &loader_api);
    }

    case KPM_CMD_LIST: {
        int pos = 0, count = 0, used_hooks = 0;
        int size = (int)(unsigned long)arg2;

        pos = buf_append(kpm_syscall_buf, size, pos, "KPM Loader Status\n");
        pos = buf_append(kpm_syscall_buf, size, pos, "=================\n");

        mutex_lock(&kpm_lock);
        struct kpm_module *mod;
        list_for_each_entry(mod, &kpm_modules, list) {
            pos = buf_append(kpm_syscall_buf, size, pos, "  ");
            pos = buf_append(kpm_syscall_buf, size, pos, mod->info.name);
            pos = buf_append(kpm_syscall_buf, size, pos, "  version=");
            pos = buf_append(kpm_syscall_buf, size, pos, mod->info.version);
            pos = buf_append(kpm_syscall_buf, size, pos, "  license=");
            pos = buf_append(kpm_syscall_buf, size, pos,
                             mod->info.license ? mod->info.license : "unknown");
            pos = buf_append(kpm_syscall_buf, size, pos, "\n");
            count++;
        }
        mutex_unlock(&kpm_lock);

        if (count == 0)
            pos = buf_append(kpm_syscall_buf, size, pos, "  (no modules loaded)\n");

        pos = buf_append(kpm_syscall_buf, size, pos, "  hook slots: ");
        for (int i = 0; i < HOOK_REGION_SLOTS; i++)
            if (hook_slots[i].used) used_hooks++;
        pos = buf_append_dec(kpm_syscall_buf, size, pos, used_hooks);
        pos = buf_append(kpm_syscall_buf, size, pos, "/");
        pos = buf_append_dec(kpm_syscall_buf, size, pos, HOOK_REGION_SLOTS);
        pos = buf_append(kpm_syscall_buf, size, pos, " used\n");

        if (backup_printk)
            pos = buf_append(kpm_syscall_buf, size, pos, "  printk hook: ACTIVE");
        if (backup_printk && cached_printk_deferred)
            pos = buf_append(kpm_syscall_buf, size, pos, " (deferred ok)");
        if (backup_printk && !cached_printk_deferred)
            pos = buf_append(kpm_syscall_buf, size, pos, " (no deferred)");
        if (backup_printk)
            pos = buf_append(kpm_syscall_buf, size, pos, "\n");

        if (pos < size) kpm_syscall_buf[pos] = 0;
        /* Print to kernel log — avoids copy_to_user which is broken
         * (hangs or faults) on this kernel's uaccess path. */
        klog("kpm_loader: LIST:\n%s", kpm_syscall_buf);
        if (arg1 && size > 0) {
            long n = pos + 1; if (n > size) n = size;
            if (compat_copy_to_user(arg1, kpm_syscall_buf, (int)n) != 0) {
                /* copy_to_user failed — caller can read dmesg instead */
            }
        }
        return pos;
    }

    case KPM_CMD_KADDR: {
        unsigned long prev = (unsigned long)(void *)kallsyms_lookup_name_fn;
        unsigned long addr = (unsigned long)arg1;
        if (addr != 0) {
            kallsyms_lookup_name_fn = (typeof(kallsyms_lookup_name_fn))addr;
            klog("kpm_loader: kallsyms_lookup_name set to %llx via syscall\n",
                   (u64)addr);
            for (int i = 0; needed_syms[i]; i++) {
                unsigned long s = kallsyms_lookup(needed_syms[i]);
                if (!s) continue;
                if (strcmp(needed_syms[i], "module_alloc") == 0)
                    cached_module_alloc = s;
                else if (strcmp(needed_syms[i], "aarch64_insn_patch_text_nosync") == 0)
                    cached_insn_patch = s;
                else if (strcmp(needed_syms[i], "__flush_icache_range") == 0 && !cached_flush_icache)
                    cached_flush_icache = s;
                else if (strcmp(needed_syms[i], "flush_icache_range") == 0 && !cached_flush_icache)
                    cached_flush_icache = s;
                else if (strcmp(needed_syms[i], "set_memory_x") == 0)
                    cached_set_memory_x = s;
                else if (strcmp(needed_syms[i], "set_memory_rw") == 0)
                    cached_set_memory_rw = s;
                else if (strcmp(needed_syms[i], "printk_deferred") == 0)
                    cached_printk_deferred = s;
                else if (strcmp(needed_syms[i], "_copy_to_user") == 0)
                    cached_copy_to_user = s;
                else if (strcmp(needed_syms[i], "raw_copy_to_user") == 0)
                    cached_raw_copy_to_user = s;
                else if (strcmp(needed_syms[i], "copy_to_user") == 0)
                    cached_raw_copy_to_user = s;
                else if (strcmp(needed_syms[i], "__arch_copy_to_user") == 0)
                    cached_arch_copy_to_user = s;
                else if (strcmp(needed_syms[i], "__copy_to_user") == 0)
                    cached_legacy_copy_to_user = s;
                else if (strcmp(needed_syms[i], "__uaccess_ttbr0_enable") == 0 && !cached_ttbr0_enable)
                    cached_ttbr0_enable = s;
                else if (strcmp(needed_syms[i], "__uaccess_ttbr0_disable") == 0 && !cached_ttbr0_disable)
                    cached_ttbr0_disable = s;
                else if (strcmp(needed_syms[i], "strncpy_from_user") == 0)
                    cached_strncpy_from_user = s;
                else if (strcmp(needed_syms[i], "__cfi_slowpath_diag") == 0 && !cached_cfi_slowpath)
                    cached_cfi_slowpath = s;
                else if (strcmp(needed_syms[i], "__cfi_slowpath") == 0 && !cached_cfi_slowpath)
                    cached_cfi_slowpath = s;
                else if (strcmp(needed_syms[i], "report_cfi_failure") == 0)
                    cached_report_cfi_failure = s;
            }
        }
        return (long)prev;
    }

    case KPM_CMD_CTL: {
        char name[128], args[256];
        long r = kp_compat_strncpy_from_user(name,
                (const char __user *)arg1, sizeof(name));
        if (r < 0) return -14;
        r = kp_compat_strncpy_from_user(args,
                (const char __user *)arg2, sizeof(args));
        if (r < 0) return -14;

        /* Always use a kernel buffer for ctl0 output.
         * compat_copy_to_user inside KPMs hangs on 6.1+ when
         * _copy_to_user/raw_copy_to_user are not exported and
         * the STTRB fallback faults (SW PAN). */
        char out[512];
        long rc = api_kpm_control(name, args, out, sizeof(out));
        klog("kpm_loader: ctl %s %s -> %ld: %s\n", name, args, rc, out);

        /* Parse backup=0x... from response and return as syscall retval.
         * This bypasses the broken userspace-copy path entirely for
         * uxn-hook/call-orig.  hook-demo reads syscall return directly. */
        {
            const char *s = out;
            while (*s) {
                if (!__builtin_strncmp(s, "backup=0x", 9)
                    || !__builtin_strncmp(s, "backup=0X", 9)) {
                    unsigned long ba = 0;
                    for (s += 9; *s; s++) {
                        char c = *s;
                        if (c >= '0' && c <= '9')
                            ba = (ba << 4) | (unsigned long)(c - '0');
                        else if (c >= 'a' && c <= 'f')
                            ba = (ba << 4) | (unsigned long)(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F')
                            ba = (ba << 4) | (unsigned long)(c - 'A' + 10);
                        else break;
                    }
                    if (ba) {
                        klog("kpm_loader: ctl returning backup=0x%lx\n", ba);
                        return (long)ba;
                    }
                    break;
                }
                s++;
            }
        }

        /* No copy_to_user — STTRB hangs on QEMU, and critical data
         * (backup= addr) is returned via syscall retval above. */
        return rc;
    }

    case KPM_CMD_BYPASS:
        bypass_kcfi();
        return 0;

    case KPM_CMD_HOOK_TEST:
        do_hook_printk();
        return 0;

    case KPM_CMD_UNHOOK_TEST:
        do_unhook_printk();
        return 0;

    default:
        return -22;
    }
}

/* Register the stolen syscall. Called from kpm_loader_init(). */
static int kpm_syscall_register(void)
{
    if (!kp_sys_call_table) {
        klog("kpm_loader: sys_call_table not found, syscall interface disabled\n");
        return -1;
    }

    /* Walk a few candidate slots. On most ARM64 kernels NR_syscalls ≈ 450;
     * we try 448 first (beyond the last real syscall on GKI 6.1). */
    unsigned long try[] = {448, 449, 450, 447, 446, 445, 0};
    for (int i = 0; try[i]; i++) {
        unsigned long nr = try[i];
        unsigned long *slot = (unsigned long *)kp_sys_call_table + nr;
        unsigned long orig = 0;

        /* Read the current entry via raw pointer — sys_call_table is
         * readable even though it's __ro_after_init. */
        orig = *slot;
        if (!orig || (orig & 0xFFF) == 0) {
            /* Likely beyond NR_syscalls — skip */
            continue;
        }

        /* Write our handler via PTE manipulation */
        kpm_syscall_nr = nr;
        kpm_syscall_original = orig;
        write_kernel_u64((u64 *)slot, (u64)&kpm_syscall_handler);

        /* On wrapper kernels, invoke_syscall() does inline kCFI check
         * (ldr w16, [x16, #-4]) on the handler. Copy the expected hash
         * from the original syscall entry and write it into our prefix
         * via PTE manipulation (the prefix is const, in RO .text). */
        if (kp_has_syscall_wrapper && orig > 4 && (orig & 0xFFF) >= 4) {
            u32 cfi_hash = *(u32 *)(orig - 4);
            u64 val = (u64)cfi_hash << 32;
            write_kernel_u64((u64 *)&kpm_handler_cfi_prefix, val);
            klog("kpm_loader: patched kCFI hash %08x for syscall handler\n",
                 cfi_hash);
        }

        klog("kpm_loader: registered syscall[%lu] orig=%llx handler=%llx\n",
               nr, (u64)orig, (u64)&kpm_syscall_handler);
        return 0;
    }

    klog("kpm_loader: no free syscall slot found\n");
    return -1;
}

static void kpm_syscall_unregister(void)
{
    if (!kpm_syscall_nr || !kpm_syscall_original) return;
    unsigned long *slot = (unsigned long *)kp_sys_call_table + kpm_syscall_nr;
    write_kernel_u64((u64 *)slot, kpm_syscall_original);
    klog("kpm_loader: unregistered syscall[%lu] restored %llx\n",
           kpm_syscall_nr, (u64)kpm_syscall_original);
    kpm_syscall_nr = 0;
    kpm_syscall_original = 0;
}

/* =========================================================================
 * Section 11: Module parameters and init/exit
 * ========================================================================= */

/* Module parameter for auto-loading a KPM at init time */
static char kpm_path_buf[256] = "";
static char *kpm_path = kpm_path_buf;

/* Kernel module parameter support — we use a simple approach:
 * The module parameter is read via the kernel's module_param mechanism.
 * Since we compile with NDK, we declare it manually.
 * The kernel resolves module_param from the .modinfo section.
 * We just need the variable to be accessible.
 */
/* module_param(kpm_path, charp, 0); — declared via .modinfo by KPatcher */

static int __init kpm_loader_init(void)
{
    /* Initialize kallsyms first — each strategy calls resolve_printk()
     * which sets klog via kallsyms_lookup_name("printk"/"_printk"). */
    kallsyms_init();

    if (!klog) {
        /* No printk available yet; module is still usable (symbols can be set
         * later via /proc/kpm_loader), but we can't log anything for now. */
    } else {
        klog("kpm_loader: initializing KPM loader\n");
    }

    /* Set API table printk pointer — must happen after resolve_printk() */
    loader_api.printk = (void *)klog;

    /* Initialize kallsyms cache */
    kallsyms_init();

    /* Initialize local symbols (kpver/kver/compat_copy_to_user) for
     * KernelPatch KPM compatibility. Must run AFTER kallsyms_init
     * because kver detection needs kallsyms_lookup("init_uts_ns"). */
    local_syms_init();

    /* Hook CFI slowpath to allow calling non-CFI KPM code.
     * Must run AFTER kallsyms cache is populated and BEFORE any KPM load. */
    bypass_kcfi();

    /* Self-test: install/unhook getpid to validate PTE write + CFI bypass. */
    {
        long rc = kp_fp_wrap_syscalln(172, 0, 0, NULL, NULL, NULL);
        klog("kpm_loader: self-test fp_hook getpid(172) -> %ld\n", rc);
        if (rc == 0) {
            kp_fp_unwrap_syscalln(172, 0, NULL, NULL);
            klog("kpm_loader: self-test fp_unhook getpid(172) done\n");
        }
    }

    /* Initialize module list and lock */
    INIT_LIST_HEAD(&kpm_modules);
    __mutex_init(&kpm_lock, "kpm_lock", &kpm_lock_key);

    /* Register custom syscall interface (replaces /proc/kpm_loader).
     * Must run AFTER self-test because that initializes kp_sys_call_table
     * via kp_syscall_hook_init(). */
    kpm_syscall_register();

    /* Auto-load KPM if path specified */
    if (kpm_path[0]) {
        klog("kpm_loader: auto-loading %s\n", kpm_path);
        load_kpm_file(kpm_path, NULL, &loader_api);
    }

    klog("kpm_loader: initialized\n");
    return 0;
}

static void __exit kpm_loader_exit(void)
{
    klog("kpm_loader: shutting down\n");

    /* Restore original syscall entry */
    kpm_syscall_unregister();

    unload_all_kpms(NULL);

    /* Uninstall all hooks */
    for (int i = 0; i < HOOK_REGION_SLOTS; i++) {
        if (hook_slots[i].used)
            hook_uninstall(&hook_slots[i].hook);
    }

    klog("kpm_loader: exited\n");
}

/* Standard kernel module entry points.
 * no_sanitize("cfi"), no_sanitize("kcfi") is WRONG here — it strips the CFI type hash,
 * so when vmlinux calls mod->exit via __cfi_slowpath it finds a
 * missing/garbage hash and panics with __cfi_check_fail.
 * The fix: let the compiler emit the CFI_ICALL hash, and ensure
 * the signature matches the kernel's struct module member type:
 * init=int(*)(void), exit=void(*)(void). */
#ifdef LOADER_CFI_STUBS
/* With external CFI stubs: the real functions are renamed so cfi_entry_stubs.S
 * can claim the init_module / cleanup_module symbols for the jump tables. */
#define INIT_SYM init_module_impl
#define EXIT_SYM cleanup_module_impl
#else
#define INIT_SYM init_module
#define EXIT_SYM cleanup_module
#endif

int INIT_SYM(void)
{
    return kpm_loader_init();
}

void EXIT_SYM(void)
{
    kpm_loader_exit();
}
