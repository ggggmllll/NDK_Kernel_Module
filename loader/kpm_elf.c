/*
 * kpm_elf.c — KPM 模块加载核心
 *
 * 移植自 examples/loader_full.c 的：
 *   Section 6 — AArch64 RELA 重定位引擎（apply_relocate_add + 辅助）
 *   Section 7 — KPM binary loader（ET_REL 解析 / 段布局 / 符号简化 /
 *               GOT 构建 / PLT 生成 / 重定位应用 / 内存可执行化 / init 调用）
 *
 * 适配模板：klog / kallsyms_lookup / mutex / vmalloc / vfree / call_*
 * 都用 include/ 提供的；filp_open 懒解析（GKI 6.1 不导出）；
 * kpm_kernel_read 用模板的 kmod_read_file。
 *
 * KPM 专属保留：call_kpm_exit（no_sanitize 调 KPM exit fn）。
 * 跨子系统：kpm_alloc/free 调 cfi_bypass 的 kpm_area_add/remove；
 *           kpm_build_got 调 kp_compat 的 is_local_data_sym。
 */
#include "kpm_internal.h"

/* =========================================================================
 * ELF64 类型 + AArch64 重定位常量（KPM loader 内部用）
 * ========================================================================= */
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

#define ELFMAG      "\177ELF"
#define SELFMAG     4
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

/* =========================================================================
 * 全局状态
 * ========================================================================= */
LIST_HEAD(kpm_modules);
struct mutex kpm_lock;
static struct lock_class_key kpm_lock_key;

void kpm_loader_init_subsys(void)
{
    INIT_LIST_HEAD(&kpm_modules);   /* LIST_HEAD 已静态初始化，这里幂等 */
    __mutex_init(&kpm_lock, "kpm_lock", &kpm_lock_key);
}

/* =========================================================================
 * Section 6: AArch64 RELA 重定位引擎
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
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((u64)(sval + 1) > 2) return -1;
    return 0;
}

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
    case 1: mask = BIT(26) - 1; shift = 0; break;
    case 2: mask = BIT(19) - 1; shift = 5; break;
    case 3: mask = BIT(16) - 1; shift = 5; break;
    case 4: mask = BIT(14) - 1; shift = 5; break;
    case 5: mask = BIT(12) - 1; shift = 10; break;
    case 6: mask = BIT(9)  - 1; shift = 12; break;
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
        case 314 /* R_AARCH64_PLT32 */:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
            break;
        case R_AARCH64_PREL16:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
            break;
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
 * ========================================================================= */

/* 前向声明：kpm_build_got / kpm_generate_plt 在定义前就用到这几个 */
static void *kpm_alloc(unsigned long size);
static void  kpm_free_exec(void *addr);
static void  kpm_make_exec(void *p, unsigned long size);
static void  kpm_flush_icache(void *start, unsigned long size);

static struct kpm_module *find_module(const char *name)
{
    struct kpm_module *mod;
    list_for_each_entry(mod, &kpm_modules, list) {
        if (strcmp(mod->info.name, name) == 0) return mod;
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

static char *next_kpm_info_str(char *p, unsigned long *remaining)
{
    while (*p) {
        p++;
        if ((*remaining)-- <= 1) return NULL;
    }
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
    u64 *got_map;
    void *got_base;
    int got_count;
    u64 *kf_wrap_pool;
    int kf_wrap_count;
    int kf_wrap_max;
};

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

static int kpm_setup_load_info(struct kpm_load_info *info)
{
    const Elf64_Ehdr *hdr = info->hdr;

    info->sechdrs = (void *)hdr + hdr->e_shoff;
    info->secstrings = (void *)hdr + info->sechdrs[hdr->e_shstrndx].sh_offset;

    info->init_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.init");
    info->exit_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.exit");
    if (info->init_idx < 0 || info->exit_idx < 0) {
        klog("kpm_loader: missing .kpm.init or .kpm.exit\n");
        return -1;
    }

    info->info_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.info");
    if (info->info_idx < 0) {
        klog("kpm_loader: missing .kpm.info section\n");
        return -1;
    }

    const char *info_base = get_section_ptr(hdr, info->sechdrs, info->info_idx);
    unsigned long info_size = info->sechdrs[info->info_idx].sh_size;

    info->name        = get_modinfo_val(info_base, info_size, "name");
    info->version     = get_modinfo_val(info_base, info_size, "version");
    info->license     = get_modinfo_val(info_base, info_size, "license");
    info->author      = get_modinfo_val(info_base, info_size, "author");
    info->description = get_modinfo_val(info_base, info_size, "description");

    if (!info->name || !info->version) {
        klog("kpm_loader: module name or version not found\n");
        return -1;
    }

    info->ctl0_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.ctl0");
    info->ctl1_idx = find_section(info->sechdrs, hdr->e_shnum, info->secstrings, ".kpm.ctl1");

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

    for (unsigned int i = 0; i < hdr->e_shnum; i++) {
        if (!info->sechdrs[i].sh_addr)
            info->sechdrs[i].sh_addr = (Elf64_Addr)((unsigned long)hdr + info->sechdrs[i].sh_offset);
    }

    return 0;
}

static unsigned long kpm_layout_sections(struct kpm_load_info *info,
                                          unsigned int *text_size,
                                          unsigned int *text_used,
                                          unsigned int *plt_offs)
{
    unsigned long total = 0;
    unsigned int shnum = info->hdr->e_shnum;

    for (unsigned int i = 1; i < shnum; i++) {
        Elf64_Shdr *s = &info->sechdrs[i];
        if (!(s->sh_flags & SHF_ALLOC)) continue;
        if (!(s->sh_flags & SHF_EXECINSTR)) continue;
        unsigned long align = s->sh_addralign ?: 1;
        total = ALIGN(total, align);
        s->sh_entsize = total;
        total += s->sh_size;
    }
    *text_used = total;
    total = ALIGN(total, PAGE_SIZE);

    *plt_offs = total;
    total += 32 * 4 * 4;          /* max 32 PLT stubs, 16 bytes each */
    total = ALIGN(total, PAGE_SIZE);
    *text_size = total;

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

        shdr->sh_addr = (unsigned long)dest;

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
            {
                unsigned long addr = kpm_kallsyms_lookup(name);
                if (!addr) {
                    char cfi_name[128];
                    unsigned long nl = strlen(name);
                    if (nl < 120) {
                        memcpy(cfi_name, name, nl);
                        memcpy(cfi_name + nl, ".cfi_jt", 8);
                        addr = kpm_kallsyms_lookup(cfi_name);
                    }
                }
                if (!addr) {
                    /* KernelPatch KPM 兼容：kf_ 前缀的函数指针符号，去掉
                     * 前缀解析底层内核函数，并用 kf_wrap_pool 包一层
                     *（GOT 双重解引用需要变量地址而非函数地址）。 */
                    unsigned long nlen = strlen(name);
                    if (nlen > 3 && name[0] == 'k' && name[1] == 'f' && name[2] == '_') {
                        addr = kpm_kallsyms_lookup(name + 3);
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

static int kpm_build_got(struct kpm_module *mod, struct kpm_load_info *info)
{
    unsigned int shnum = info->hdr->e_shnum;
    int nsyms = (int)(info->sechdrs[info->sym_idx].sh_size / sizeof(Elf64_Sym));

    info->got_map = vmalloc(nsyms * sizeof(u64));
    if (!info->got_map) return -1;
    memset(info->got_map, 0, nsyms * sizeof(u64));
    info->got_count = 0;

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
                    info->got_map[sym_idx] = 1;
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

    info->got_base = kpm_alloc(info->got_count * 8);
    if (!info->got_base) { vfree(info->got_map); info->got_map = NULL; return -1; }

    Elf64_Sym *syms = (void *)info->sechdrs[info->sym_idx].sh_addr;
    u64 *slot = (u64 *)info->got_base;
    klog("kpm_loader: GOT base=%px count=%d\n", info->got_base, info->got_count);
    for (int s = 0; s < nsyms; s++) {
        if (info->got_map[s]) {
            const char *sname = info->strtab + syms[s].st_name;
            u64 val = syms[s].st_value;
            bool need_wrap = false;
            if (syms[s].st_shndx == SHN_UNDEF) {
                /* kpm_simplify_symbols 已把 kf_ 符号的 st_value 设成 wrap 槽
                 * 的【地址】(&kf_wrap_pool[k])。这里若 val 已落在 wrap_pool
                 * 地址区间内，说明已经包过，绝不能再包 —— 否则 KPM 双重解引用
                 * 后会落在 wrap 槽(数据,NX)而非真函数地址 → 执行 NX 崩。
                 * 原代码比的是 val==kf_wrap_pool[w](槽内容,=真函数地址)，永远
                 * 不等于槽地址 → 误判没包过 → 重复包装的 bug。 */
                bool already_wrapped = false;
                if (info->kf_wrap_pool) {
                    u64 lo = (u64)info->kf_wrap_pool;
                    u64 hi = lo + (u64)info->kf_wrap_max * sizeof(u64);
                    if (val >= lo && val < hi) already_wrapped = true;
                }
                if (!already_wrapped && !is_local_data_sym((unsigned long)val)) {
                    need_wrap = true;
                }
            }
            if (need_wrap) {
                if (info->kf_wrap_count >= info->kf_wrap_max) {
                    klog("kpm_loader: GOT-wrap pool exhausted (%d)\n", info->kf_wrap_max);
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

static int plt_gen_entry(u32 *entry, unsigned long target)
{
    entry[0] = 0x58000050;  /* ldr x16, #8 */
    entry[1] = 0xd61f0200;  /* br x16 */
    entry[2] = (u32)(target & 0xffffffffUL);
    entry[3] = (u32)(target >> 32);
    return 4;
}

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

/* no_sanitize：KPM 代码没有 CFI 类型 hash，间接调用会撞 CFI。 */
__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long call_kpm_exit(kpm_exitcall_t fn, void *reserved)
{
    klog("kpm_loader: call_kpm_exit fn=%px reserved=%px\n", fn, reserved);
    return fn(reserved);
}

__attribute__((no_sanitize("cfi"), no_sanitize("kcfi")))
static long call_kpm_ctl0(kpm_ctl0call_t fn, const char *args,
                           char *out_msg, int outlen)
{
    return fn(args, out_msg, outlen);
}

/* CTL 命令：按名查模块，调它的 ctl0 回调。供 kpm_syscall 的 CTL 命令用。 */
long api_kpm_control(const char *name, const char *args, char *out_msg, int outlen)
{
    struct kpm_module *mod;
    mutex_lock(&kpm_lock);
    mod = find_module(name);
    mutex_unlock(&kpm_lock);
    if (!mod || !mod->ctl0 || !*mod->ctl0) return -1;
    return call_kpm_ctl0(*mod->ctl0, args, out_msg, outlen);
}

/* filp_open / 读整文件已收敛到 kmod_kernel.c 的 kmod_read_whole_file。 */

static void *kpm_alloc(unsigned long size)
{
    /* vmalloc + kpm_make_exec(set_memory_x) 设可执行。set_memory_x 只认
     * VM_ALLOC + 在 vmalloc 区，与地址范围无关，vmalloc 完全够用。 */
    void *p = vmalloc(size);
    if (!p) return NULL;
    memset(p, 0, size);
    kpm_area_add((unsigned long)p, size);
    return p;
}

static void kpm_make_exec(void *p, unsigned long size)
{
    int np = (int)((size + PAGE_SIZE - 1) / PAGE_SIZE);
    int rc = call_set_memory_x((unsigned long)p, np);
    if (rc)
        klog("kpm_loader: set_memory_x(%px, %d) FAILED: %d\n", p, np, rc);
}

static void kpm_free_exec(void *addr)
{
    if (addr)
        kpm_area_remove((unsigned long)addr);
    vfree(addr);
}

static void kpm_flush_icache(void *start, unsigned long size)
{
    call_flush_icache((unsigned long)start, (unsigned long)start + size);
}

/* =========================================================================
 * 加载主流程
 * ========================================================================= */
static long load_kpm_from_data(const void *data, unsigned long len,
                                const char *args, const char *event)
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

    mutex_lock(&kpm_lock);
    if (find_module(load_info.name)) {
        klog("kpm_loader: module '%s' already loaded\n", load_info.name);
        mutex_unlock(&kpm_lock);
        return -2;
    }
    mutex_unlock(&kpm_lock);

    struct kpm_module *mod = vmalloc(sizeof(*mod));
    if (!mod) return -3;
    memset(mod, 0, sizeof(*mod));

    if (args) {
        unsigned long alen = strlen(args);
        mod->args = vmalloc(alen + 1);
        if (mod->args) strcpy(mod->args, args);
    }

    unsigned int text_size, text_used, plt_offs;
    mod->size = kpm_layout_sections(&load_info, &text_size, &text_used, &plt_offs);
    mod->text_size = text_size;
    mod->text_used = text_used;
    unsigned long plt_max = 32;

    mod->start = kpm_alloc(mod->size);
    if (!mod->start) {
        klog("kpm_loader: failed to allocate %u bytes\n", mod->size);
        vfree(mod);
        return -3;
    }
    memset(mod->start, 0, mod->size);

    if (kpm_move_sections(mod, &load_info, mod->start)) {
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }

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

    if (kpm_build_got(mod, &load_info)) {
        klog("kpm_loader: GOT build FAILED\n");
        if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }

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

    if (kpm_apply_relocations(mod, &load_info)) {
        klog("kpm_loader: relocation FAILED\n");
        if (load_info.got_base) kpm_free_exec(load_info.got_base);
        if (load_info.got_map) vfree(load_info.got_map);
        if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
        kpm_free_exec(mod->start);
        vfree(mod);
        return -1;
    }
    if (load_info.got_map) { vfree(load_info.got_map); load_info.got_map = NULL; }
    klog("kpm_loader: relocations applied, about to make exec\n");

    /* Fixup: -fno-PIC 函数调用模式 LDR→ADD。
     * ET_REL -fno-PIC 生成 adrp+ldr+blr，重定位后 ldr 从函数自身代码字节
     * 读"指针"导致 blr 跳到指令当地址。把 LDR 改成 ADD（xM = sym 地址）。
     * 用 reloc 条目的 sym_value 算 ADD 立即数，保留 [2:0] 位（避免对到
     * kCFI 4 字节对齐的 type hash）。*/
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
                if ((insn & 0xFFC00000) != 0xF9400000) continue;  /* 64-bit LDR unsigned imm */
                /* OBJECT/SECTION 符号要保留 LDR（它读存好的指针值）*/
                {
                    Elf64_Sym *ck_sym = (Elf64_Sym *)load_info.sechdrs[symindex].sh_addr
                                        + ELF64_R_SYM(rel[j].r_info);
                    unsigned char stt = ELF64_ST_TYPE(ck_sym->st_info);
                    if (stt == STT_OBJECT || stt == STT_SECTION)
                        continue;
                }
                unsigned int ldst_reg = insn & 0x1F;
                int converted = 0;
                /* 向后看最多 16 条指令，找通过同寄存器的 BLR/BR */
                for (int k = 1; k <= 16 && !converted; k++) {
                    u32 *next = loc + k;
                    if ((unsigned long)next >= sec_end) break;
                    u32 next_insn = *next;
                    /* 中间有指令写该寄存器 → LDR→BLR 链断，不转 */
                    if ((next_insn & 0x1F) == ldst_reg && next_insn != insn)
                        break;
                    /* BLR Xn: 0xD63F0000 | (n<<5) */
                    if ((next_insn & 0xFFFFFC1F) == 0xD63F0000 &&
                        (unsigned int)((next_insn >> 5) & 0x1F) == ldst_reg) {
                        Elf64_Sym *r_sym = (Elf64_Sym *)load_info.sechdrs[symindex].sh_addr
                                           + ELF64_R_SYM(rel[j].r_info);
                        u64 sym_val = r_sym->st_value + rel[j].r_addend;
                        unsigned int add_imm12 = sym_val & 0xFFF;
                        *loc = 0x91000000 | (add_imm12 << 10) | (insn & 0x3FF);
                        fixed++; converted = 1;
                    }
                    /* BR Xn: 0xD61F0000 | (n<<5) */
                    if (!converted &&
                        (next_insn & 0xFFFFFC1F) == 0xD61F0000 &&
                        (unsigned int)((next_insn >> 5) & 0x1F) == ldst_reg) {
                        Elf64_Sym *r_sym = (Elf64_Sym *)load_info.sechdrs[symindex].sh_addr
                                           + ELF64_R_SYM(rel[j].r_info);
                        u64 sym_val = r_sym->st_value + rel[j].r_addend;
                        unsigned int add_imm12 = sym_val & 0xFFF;
                        *loc = 0x91000000 | (add_imm12 << 10) | (insn & 0x3FF);
                        fixed++; converted = 1;
                    }
                }
            }
        }
        if (fixed) klog("kpm_loader: fixed %d LDR->ADD for function calls\n", fixed);
    }

    /* Make executable + flush icache（.text 和 PLT 都在 text_size 内）*/
    kpm_make_exec(mod->start, text_size);
    kpm_flush_icache(mod->start, text_size);
    if (plt_stubs > 0)
        klog("kpm_loader: PLT %d stubs @ %lx (inside exec region)\n",
             plt_stubs, plt_area_addr);
    klog("kpm_loader: icache flushed, about to call KPM init\n");

    /* 加入链表（init 前加，便于 hook 查 KPM text 页）*/
    mod->got_base = load_info.got_base;
    load_info.got_base = NULL;
    mutex_lock(&kpm_lock);
    list_add_tail(&mod->list, &kpm_modules);
    mutex_unlock(&kpm_lock);

    long rc = 0;
    if (mod->init && *mod->init) {
        u64 volatile fn_addr = *(u64 *)mod->init;
        kpm_initcall_t init_fn = (kpm_initcall_t)fn_addr;
        klog("kpm_loader: calling init_fn at %px (raw=0x%llx)\n", init_fn, fn_addr);
        rc = init_fn(mod->args, event, NULL);
        klog("kpm_loader: init_fn returned %ld\n", rc);
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
    } else {
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

    if (load_info.kf_wrap_pool) vfree(load_info.kf_wrap_pool);
    load_info.kf_wrap_pool = NULL;
    return 0;
}

long load_kpm_file(const char *path, const char *args)
{
    if (!path) return -1;

    long size = 0;
    void *data = kmod_read_whole_file(path, &size, 0);
    if (!data || size <= 0) {
        klog("kpm_loader: cannot read %s\n", path);
        return -1;
    }

    klog("kpm_loader: read %s (%ld bytes), parsing KPM\n", path, size);
    long rc = load_kpm_from_data(data, size, args, "load-file");
    vfree(data);
    return rc;
}

long unload_kpm_name(const char *name)
{
    if (!name) return -1;

    mutex_lock(&kpm_lock);
    struct kpm_module *mod = find_module(name);
    if (!mod) {
        mutex_unlock(&kpm_lock);
        return -2;
    }
    list_del(&mod->list);
    mutex_unlock(&kpm_lock);

    if (mod->exit && *mod->exit) {
        kpm_exitcall_t exit_fn = *mod->exit;
        klog("kpm_loader: calling KPM exit\n");
        call_kpm_exit(exit_fn, NULL);
        klog("kpm_loader: KPM exit returned\n");
    }

    /* 等所有 CPU 过 quiescent 状态，确保没有 CPU 还在执行 KPM 代码页。
     * 不用 stop_machine 做 per-CPU ICache drain（loader 自身的 kpm_drain_cpu
     * kCFI hash 和内核期望的不匹配，会在 multi_cpu_stop 里撞 kCFI）。 */
    klog("kpm_loader: synchronize_rcu before kpm_free_exec\n");
    call_synchronize_rcu();
    klog("kpm_loader: synchronize_rcu done\n");

    klog("kpm_loader: unloading module '%s'\n", mod->info.name);

    if (mod->args)      { vfree(mod->args); }
    if (mod->ctl_args)  { vfree(mod->ctl_args); }
    if (mod->got_base)  { kpm_free_exec(mod->got_base); }
    kpm_free_exec(mod->start);
    vfree(mod);
    return 0;
}

long unload_all_kpms(void)
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
            call_kpm_exit(exit_fn, NULL);
        }

        klog("kpm_loader: unloading module '%s'\n", mod->info.name);

        if (mod->args)     vfree(mod->args);
        if (mod->ctl_args) vfree(mod->ctl_args);
        if (mod->got_base) kpm_free_exec(mod->got_base);
        kpm_free_exec(mod->start);
        vfree(mod);
        count++;
    }
    mutex_unlock(&kpm_lock);

    return count;
}
