/*
 * fixup_ko.c - Patch a KPatcher-generated .ko with kernel-specific values
 *
 * Reads a reference .ko (from the target system) to extract:
 *   - vermagic string (from .modinfo section)
 *   - module_layout CRC (from __versions section)
 * Then patches the KPatcher-generated .ko in-place.
 *
 * This program uses only standard C and <elf.h> — no external dependencies.
 * It can be compiled on the Android target with any C compiler.
 *
 * Compile: cc -o fixup_ko fixup_ko.c -Wall
 * Usage:   ./fixup_ko <target.ko>
 *          ./fixup_ko <reference.ko> <target.ko>
 */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define MODULE_NAME_LEN_64 56
#define MODULE_NAME_LEN_32 60
#define MODVERSION_INFO_SIZE_64 64  /* 8 (crc) + 56 (name) */
#define MODVERSION_INFO_SIZE_32 64  /* 4 (crc) + 60 (name), same total size */

/* ---------- ELF file wrapper ---------- */
typedef struct {
	void  *map;
	size_t size;
	int    is64;
} ElfFile;

static int elf_open(const char *path, ElfFile *ef, int for_write) {
	int fd = open(path, for_write ? O_RDWR : O_RDONLY);
	if (fd < 0) return -1;

	struct stat st;
	if (fstat(fd, &st) < 0) { close(fd); return -1; }
	if (st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); return -1; }

	ef->size = (size_t)st.st_size;
	ef->map  = mmap(NULL, ef->size,
	                for_write ? (PROT_READ | PROT_WRITE) : PROT_READ,
	                for_write ? MAP_SHARED : MAP_PRIVATE, fd, 0);
	close(fd);

	if (ef->map == MAP_FAILED) return -1;

	unsigned char *e = (unsigned char *)ef->map;
	if (e[EI_MAG0] != 0x7F || e[EI_MAG1] != 'E' ||
	    e[EI_MAG2] != 'L'  || e[EI_MAG3] != 'F') {
		munmap(ef->map, ef->size);
		return -1;
	}
	ef->is64 = (e[EI_CLASS] == ELFCLASS64);
	return 0;
}

static void elf_close(ElfFile *ef) {
	if (ef->map && ef->map != MAP_FAILED) {
		msync(ef->map, ef->size, MS_SYNC);
		munmap(ef->map, ef->size);
	}
}

/* ---------- ELF section lookup ---------- */
/* Returns pointer to the section data, or NULL. Sets *out_size. */
static void *elf_section_data(ElfFile *ef, const char *name, size_t *out_size) {
	if (ef->is64) {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ef->map;
		Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)ef->map + ehdr->e_shoff);
		uint16_t shstrndx = ehdr->e_shstrndx;
		if (shstrndx >= ehdr->e_shnum) return NULL;
		const char *shstrtab = (const char *)ef->map + shdr[shstrndx].sh_offset;

		for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
			const char *sname = shstrtab + shdr[i].sh_name;
			if (strcmp(sname, name) == 0) {
				if (out_size) *out_size = (size_t)shdr[i].sh_size;
				if (shdr[i].sh_type == SHT_NOBITS) return NULL;
				return (char *)ef->map + shdr[i].sh_offset;
			}
		}
	} else {
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ef->map;
		Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)ef->map + ehdr->e_shoff);
		uint16_t shstrndx = ehdr->e_shstrndx;
		if (shstrndx >= ehdr->e_shnum) return NULL;
		const char *shstrtab = (const char *)ef->map + shdr[shstrndx].sh_offset;

		for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
			const char *sname = shstrtab + shdr[i].sh_name;
			if (strcmp(sname, name) == 0) {
				if (out_size) *out_size = (size_t)shdr[i].sh_size;
				if (shdr[i].sh_type == SHT_NOBITS) return NULL;
				return (char *)ef->map + shdr[i].sh_offset;
			}
		}
	}
	return NULL;
}

/* ---------- Vermagic extraction ---------- */
/*
 * .modinfo contains null-separated key=value pairs.
 * Look for "vermagic=" and return a pointer to the value (static buffer).
 */
static const char *extract_vermagic(ElfFile *ef) {
	size_t size;
	const char *data = (const char *)elf_section_data(ef, ".modinfo", &size);
	if (!data) return NULL;

	const char *end = data + size;
	const char *p   = data;
	while (p < end) {
		if (strncmp(p, "vermagic=", 9) == 0) {
			/* Return pointer into the mapped data */
			return p + 9;
		}
		/* advance to next null-terminated string */
		while (p < end && *p != '\0') p++;
		p++; /* skip null */
	}
	return NULL;
}

/* ---------- Module name extraction ---------- */
static const char *extract_module_name(ElfFile *ef) {
	size_t size;
	const char *data = (const char *)elf_section_data(ef, ".modinfo", &size);
	if (!data) return NULL;
	const char *end = data + size;
	for (const char *p = data; p < end; ) {
		if (strncmp(p, "name=", 5) == 0) return p + 5;
		while (p < end && *p != '\0') p++;
		p++;
	}
	return NULL;
}

/* Find byte offset of a string within a buffer, or -1 if not found */
static long find_string_offset(const char *data, size_t size, const char *needle) {
	size_t n = strlen(needle);
	if (n == 0 || n > size) return -1;
	for (size_t i = 0; i <= size - n; i++) {
		if (memcmp(data + i, needle, n) == 0) return (long)i;
	}
	return -1;
}

/* Get writable pointer to a section header by name */
static void *elf_section_header(ElfFile *ef, const char *name) {
	if (ef->is64) {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ef->map;
		Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)ef->map + ehdr->e_shoff);
		uint16_t shstrndx = ehdr->e_shstrndx;
		if (shstrndx >= ehdr->e_shnum) return NULL;
		const char *shstrtab = (const char *)ef->map + shdr[shstrndx].sh_offset;
		for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
			if (strcmp(shstrtab + shdr[i].sh_name, name) == 0)
				return &shdr[i];
		}
	} else {
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ef->map;
		Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)ef->map + ehdr->e_shoff);
		uint16_t shstrndx = ehdr->e_shstrndx;
		if (shstrndx >= ehdr->e_shnum) return NULL;
		const char *shstrtab = (const char *)ef->map + shdr[shstrndx].sh_offset;
		for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
			if (strcmp(shstrtab + shdr[i].sh_name, name) == 0)
				return &shdr[i];
		}
	}
	return NULL;
}

/* ---------- Signature detection ---------- */
#define MODULE_SIG_MAGIC "~Module signature appended~\n"
#define MODULE_SIG_MAGIC_LEN 28

/*
 * Check whether a .ko file has a module signature appended.
 * Returns 1 if signed, 0 if not, -1 on error.
 */
static int check_signature(ElfFile *ef) {
	if (ef->size < MODULE_SIG_MAGIC_LEN) return 0;
	const char *tail = (const char *)ef->map + ef->size - MODULE_SIG_MAGIC_LEN;
	return (memcmp(tail, MODULE_SIG_MAGIC, MODULE_SIG_MAGIC_LEN) == 0) ? 1 : 0;
}

/* ---------- Patching ---------- */
/*
 * Replace the vermagic value in the target .modinfo with the full
 * vermagic string extracted from the reference .ko.
 *
 * The target has a placeholder like:
 *   vermagic=PLACEHOLDER_KERNEL_VERSION <suffix>\0
 * The reference has the real value like:
 *   vermagic=5.10.198 <suffix>\0
 *
 * We replace the entire value (everything between "vermagic=" and the
 * terminating \0) with the reference's vermagic value, null-padded.
 */
static int patch_vermagic(ElfFile *ef, const char *ref_vermagic) {
	size_t size;
	char *data = (char *)elf_section_data(ef, ".modinfo", &size);
	if (!data) {
		fprintf(stderr, "Error: .modinfo section not found in target\n");
		return -1;
	}

	/* Find "vermagic=" in target */
	const char *end = data + size;
	char *vermagic_key = NULL;
	for (char *p = data; p < end; ) {
		if (strncmp(p, "vermagic=", 9) == 0) {
			vermagic_key = p;
			break;
		}
		while (p < end && *p != '\0') p++;
		p++;
	}

	if (!vermagic_key) {
		fprintf(stderr, "Error: vermagic= not found in target .modinfo\n");
		return -1;
	}

	/* Find the end of the target's vermagic value.
	 * KPatcher uses an oversized placeholder (123+ chars) so there
	 * may be plenty of null padding after the current value.
	 * Scan forward through contiguous nulls to find the real
	 * available space so we don't truncate needlessly. */
	char *val_start = vermagic_key + 9;
	char *val_end   = val_start;
	while (val_end < end && *val_end != '\0') val_end++;
	/* val_end now points to the first null; skip forward through
	 * any additional null padding (leftover from KPatcher
	 * placeholder or a previous shorter vermagic patch). */
	char *max_end  = val_end;
	while (max_end < end && *max_end == '\0') max_end++;
	/* max_end is now the first non-null byte after the null run,
	 * i.e. the start of the next key=value pair. */
	size_t available_len = (size_t)(max_end - val_start);

	/* Length of the reference vermagic value */
	size_t ref_len = strlen(ref_vermagic);

	if (ref_len > available_len) {
		fprintf(stderr, "Warning: reference vermagic truncated (%zu > %zu)\n",
				ref_len, available_len);
		fprintf(stderr, "  Reference: %s\n", ref_vermagic);
		ref_len = available_len;
	}

	/* Overwrite with reference vermagic + null padding */
	memcpy(val_start, ref_vermagic, ref_len);
	if (ref_len < available_len)
		memset(val_start + ref_len, 0, available_len - ref_len);

	printf("Patched vermagic: %s\n", ref_vermagic);
	return 0;
}

/* ---------- CRC extraction ---------- */
static int extract_crc(ElfFile *ef, const char *sym_name,
                       unsigned long *out_crc, size_t *out_crc_size) {
	size_t size;
	char *data = (char *)elf_section_data(ef, "__versions", &size);
	if (!data) return 0;

	size_t entry_size = ef->is64 ? MODVERSION_INFO_SIZE_64 : MODVERSION_INFO_SIZE_32;
	size_t crc_size   = ef->is64 ? sizeof(uint64_t) : sizeof(uint32_t);
	size_t name_off   = crc_size;
	size_t name_max   = entry_size - crc_size;

	for (size_t off = 0; off + entry_size <= size; off += entry_size) {
		const char *entry_name = data + off + name_off;
		if (strncmp(entry_name, sym_name, name_max) == 0) {
			memcpy(out_crc, data + off, crc_size);
			*out_crc_size = crc_size;
			return 1;
		}
	}
	return 0;
}

/*
 * Patch module_layout CRC in __versions section of the target.
 */
static int patch_crc(ElfFile *ef, unsigned long crc, size_t crc_size) {
	size_t size;
	char *data = (char *)elf_section_data(ef, "__versions", &size);
	if (!data) {
		fprintf(stderr, "Error: __versions section not found in target\n");
		return -1;
	}

	size_t entry_size = ef->is64 ? MODVERSION_INFO_SIZE_64 : MODVERSION_INFO_SIZE_32;
	size_t name_off   = crc_size;
	size_t name_max   = entry_size - crc_size;

	for (size_t off = 0; off + entry_size <= size; off += entry_size) {
		const char *entry_name = data + off + name_off;
		if (strncmp(entry_name, "module_layout", name_max) == 0) {
			memcpy(data + off, &crc, crc_size);
			printf("Patched module_layout CRC: 0x%lx\n", crc);
			return 0;
		}
	}

	fprintf(stderr, "Error: module_layout not found in target __versions\n");
	return -1;
}

/*
 * Patch .gnu.linkonce.this_module.
 *
 * We keep KPatcher's clean 2048-byte placeholder instead of copying the
 * reference's entire struct module (which contains stale pointers from a
 * different kernel and causes rmmod crashes).
 *
 * The module name is left as KPatcher wrote it (via -n <MODULE_NAME>): pass
 * new_name = NULL to leave it untouched and only report it. A non-NULL
 * new_name overwrites the name (kept for callers that explicitly want to
 * rename); never feed it the reference .ko's name — see the call site.
 *
 * The init/exit relocation offsets are handled separately by
 * patch_rela_offsets().
 */
static int patch_this_module(ElfFile *ef, ElfFile *ref_ef,
                             const char *ref_name, const char *new_name) {
	size_t tgt_size;
	char *tgt_data = (char *)elf_section_data(
	    ef, ".gnu.linkonce.this_module", &tgt_size);
	if (!tgt_data) {
		fprintf(stderr, "Warning: target has no .gnu.linkonce.this_module\n");
		return 0;
	}
	(void)ref_ef;
	(void)ref_name;

	/* KPatcher places the name at offset 24 (64-bit) or 16 (32-bit) */
	size_t name_off = ef->is64 ? 24 : 16;
	size_t name_max = ef->is64 ? MODULE_NAME_LEN_64 : MODULE_NAME_LEN_32;

	if (new_name && new_name[0]) {
		/* Explicit rename requested */
		size_t name_len = strlen(new_name);
		if (name_len > name_max - 1) name_len = name_max - 1;
		memset(tgt_data + name_off, 0, name_max);
		memcpy(tgt_data + name_off, new_name, name_len);
		printf("Patched this_module: size %zu, name set to '%s' at offset %zu\n",
		       tgt_size, new_name, name_off);
	} else {
		/* Keep KPatcher's name; just report it (NUL-terminated for safety) */
		char cur[MODULE_NAME_LEN_64];
		size_t n = name_max < sizeof(cur) ? name_max : sizeof(cur);
		memcpy(cur, tgt_data + name_off, n - 1);
		cur[n - 1] = '\0';
		printf("Patched this_module: size %zu, name kept as '%s' at offset %zu\n",
		       tgt_size, cur, name_off);
	}
	return 0;
}

/* ---------- Symbol lookup ---------- */
/*
 * Find a symbol index by name in the symbol table.
 * Returns the symbol index (>=0), or -1 if not found.
 */
static int find_symbol_index(ElfFile *ef, const char *name) {
	if (ef->is64) {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ef->map;
		Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)ef->map + ehdr->e_shoff);
		uint16_t shstrndx = ehdr->e_shstrndx;
		if (shstrndx >= ehdr->e_shnum) return -1;
		const char *shstrtab = (const char *)ef->map + shdr[shstrndx].sh_offset;

		/* Find .symtab and .strtab */
		Elf64_Sym *symtab = NULL;
		size_t symcount = 0;
		const char *strtab = NULL;
		for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
			const char *sname = shstrtab + shdr[i].sh_name;
			if (strcmp(sname, ".symtab") == 0 && shdr[i].sh_type == SHT_SYMTAB) {
				symtab = (Elf64_Sym *)((char *)ef->map + shdr[i].sh_offset);
				symcount = shdr[i].sh_size / sizeof(Elf64_Sym);
				uint32_t strndx = shdr[i].sh_link;
				if (strndx < ehdr->e_shnum)
					strtab = (const char *)ef->map + shdr[strndx].sh_offset;
			}
		}
		if (!symtab || !strtab) return -1;
		for (size_t i = 0; i < symcount; i++) {
			const char *sname = strtab + symtab[i].st_name;
			if (strcmp(sname, name) == 0) return (int)i;
		}
	} else {
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ef->map;
		Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)ef->map + ehdr->e_shoff);
		uint16_t shstrndx = ehdr->e_shstrndx;
		if (shstrndx >= ehdr->e_shnum) return -1;
		const char *shstrtab = (const char *)ef->map + shdr[shstrndx].sh_offset;

		Elf32_Sym *symtab = NULL;
		size_t symcount = 0;
		const char *strtab = NULL;
		for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
			const char *sname = shstrtab + shdr[i].sh_name;
			if (strcmp(sname, ".symtab") == 0 && shdr[i].sh_type == SHT_SYMTAB) {
				symtab = (Elf32_Sym *)((char *)ef->map + shdr[i].sh_offset);
				symcount = shdr[i].sh_size / sizeof(Elf32_Sym);
				uint32_t strndx = shdr[i].sh_link;
				if (strndx < ehdr->e_shnum)
					strtab = (const char *)ef->map + shdr[strndx].sh_offset;
			}
		}
		if (!symtab || !strtab) return -1;
		for (size_t i = 0; i < symcount; i++) {
			const char *sname = strtab + symtab[i].st_name;
			if (strcmp(sname, name) == 0) return (int)i;
		}
	}
	return -1;
}

/* ---------- Relocation offset patching ---------- */
/*
 * Patch the .rela.gnu.linkonce.this_module relocation offsets to
 * match the reference .ko.  This ensures init/exit function pointers
 * land at the correct offsets within struct module even when the
 * target kernel's struct module layout differs from KPatcher's
 * hardcoded defaults.
 */
static int patch_rela_offsets(ElfFile *ef, ElfFile *ref_ef) {
	size_t ref_size, tgt_size;
	char *ref_data = (char *)elf_section_data(
	    ref_ef, ".rela.gnu.linkonce.this_module", &ref_size);
	char *tgt_data = (char *)elf_section_data(
	    ef, ".rela.gnu.linkonce.this_module", &tgt_size);

	if (!ref_data || !tgt_data) {
		fprintf(stderr, "Note: .rela.gnu.linkonce.this_module missing "
		        "in one of the files, skipping offset fixup\n");
		return 0;
	}

	/* Get symbol indices for init_module / cleanup_module */
	int tgt_init_idx  = find_symbol_index(ef, "init_module");
	int tgt_exit_idx  = find_symbol_index(ef, "cleanup_module");
	int ref_init_idx  = find_symbol_index(ref_ef, "init_module");
	int ref_exit_idx  = find_symbol_index(ref_ef, "cleanup_module");

	if (tgt_init_idx < 0 || tgt_exit_idx < 0) {
		fprintf(stderr, "Note: init_module/cleanup_module not found "
		        "in target symtab, skipping offset fixup\n");
		return 0;
	}

	/* Extract reference offsets for init and exit */
	uint64_t ref_init_off = 0, ref_exit_off = 0;
	int ref_found = 0;

	if (ref_ef->is64) {
		size_t n = ref_size / sizeof(Elf64_Rela);
		Elf64_Rela *rels = (Elf64_Rela *)ref_data;
		for (size_t i = 0; i < n && ref_found < 2; i++) {
			uint32_t sym = (uint32_t)(rels[i].r_info >> 32);
			if (ref_init_idx >= 0 && (int)sym == ref_init_idx) {
				ref_init_off = rels[i].r_offset;
				ref_found++;
			} else if (ref_exit_idx >= 0 && (int)sym == ref_exit_idx) {
				ref_exit_off = rels[i].r_offset;
				ref_found++;
			}
		}
	} else {
		size_t n = ref_size / sizeof(Elf32_Rela);
		Elf32_Rela *rels = (Elf32_Rela *)ref_data;
		for (size_t i = 0; i < n && ref_found < 2; i++) {
			uint32_t sym = rels[i].r_info >> 8;
			if (ref_init_idx >= 0 && (int)sym == ref_init_idx) {
				ref_init_off = rels[i].r_offset;
				ref_found++;
			} else if (ref_exit_idx >= 0 && (int)sym == ref_exit_idx) {
				ref_exit_off = rels[i].r_offset;
				ref_found++;
			}
		}
	}

	if (ref_found < 2) {
		fprintf(stderr, "Error: reference .ko missing init/exit relocations\n");
		return -1;
	}

	/* Patch target relocation offsets */
	int patched = 0;
	if (ef->is64) {
		size_t n = tgt_size / sizeof(Elf64_Rela);
		Elf64_Rela *rels = (Elf64_Rela *)tgt_data;
		for (size_t i = 0; i < n; i++) {
			uint32_t sym = (uint32_t)(rels[i].r_info >> 32);
			if ((int)sym == tgt_init_idx && rels[i].r_offset != ref_init_off) {
				printf("  Fixing init offset: 0x%llx -> 0x%llx\n",
				       (unsigned long long)rels[i].r_offset,
				       (unsigned long long)ref_init_off);
				rels[i].r_offset = ref_init_off;
				patched++;
			} else if ((int)sym == tgt_exit_idx && rels[i].r_offset != ref_exit_off) {
				printf("  Fixing exit offset: 0x%llx -> 0x%llx\n",
				       (unsigned long long)rels[i].r_offset,
				       (unsigned long long)ref_exit_off);
				rels[i].r_offset = ref_exit_off;
				patched++;
			}
		}
	} else {
		size_t n = tgt_size / sizeof(Elf32_Rela);
		Elf32_Rela *rels = (Elf32_Rela *)tgt_data;
		for (size_t i = 0; i < n; i++) {
			uint32_t sym = rels[i].r_info >> 8;
			if ((int)sym == tgt_init_idx && rels[i].r_offset != ref_init_off) {
				printf("  Fixing init offset: 0x%x -> 0x%lx\n",
				       rels[i].r_offset, (unsigned long)ref_init_off);
				rels[i].r_offset = (uint32_t)ref_init_off;
				patched++;
			} else if ((int)sym == tgt_exit_idx && rels[i].r_offset != ref_exit_off) {
				printf("  Fixing exit offset: 0x%x -> 0x%lx\n",
				       rels[i].r_offset, (unsigned long)ref_exit_off);
				rels[i].r_offset = (uint32_t)ref_exit_off;
				patched++;
			}
		}
	}

	if (patched > 0)
		printf("Patched %d relocation offset(s) in .rela.gnu.linkonce.this_module\n",
		       patched);
	return 0;
}

/* ---------- /proc/kallsyms read ---------- */
#define KALLSYMS_MARKER "KPM_KALLSYMS_NAME_PATCH_SLOT_V1X"
#define KALLSYMS_MARKER_LEN 32

/*
 * Read /proc/kallsyms and extract the address of kallsyms_lookup_name.
 * Returns the address, or 0 on failure (kptr_restrict may be != 0).
 */
static unsigned long read_kallsyms_lookup_name(void) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "Note: cannot open /proc/kallsyms (are we root?)\n");
        return 0;
    }

    char line[256];
    unsigned long addr = 0;
    while (fgets(line, sizeof(line), f)) {
        char *sym = strstr(line, " kallsyms_lookup_name");
        if (!sym) sym = strstr(line, " T kallsyms_lookup_name");
        if (sym) {
            /* Parse hex address at start of line */
            char *end = line;
            while (*end && *end != ' ') end++;
            if (end > line) {
                *end = '\0';
                addr = strtoul(line, NULL, 16);
                /* Verify it looks like a kernel address */
                if (addr >= 0xffff000000000000UL || addr == 0) {
                    break;
                }
                addr = 0;
            }
        }
    }
    fclose(f);

    if (addr)
        printf("kallsyms_lookup_name from /proc/kallsyms: 0x%lx\n", addr);
    else
        fprintf(stderr, "Note: kallsyms_lookup_name not found in /proc/kallsyms "
                "(kptr_restrict may be non-zero)\n");
    return addr;
}

/*
 * Find the KPM_KALLSYMS_NAME_PATCH_SLOT_V1X marker in the target ELF
 * and patch the 8 bytes immediately following it with the given address.
 * Marker is exactly 32 bytes, so addr sits at offset+32 (8-byte aligned).
 * Returns 0 on success, -1 if marker not found.
 */
static int patch_kallsyms_marker(ElfFile *ef, unsigned long addr) {
    for (size_t off = 0; off + KALLSYMS_MARKER_LEN + 8 <= ef->size; off++) {
        if (memcmp((char *)ef->map + off, KALLSYMS_MARKER,
                   KALLSYMS_MARKER_LEN) == 0) {
            size_t addr_off = off + KALLSYMS_MARKER_LEN;
            if (ef->is64) {
                uint64_t *slot = (uint64_t *)((char *)ef->map + addr_off);
                *slot = (uint64_t)addr;
            } else {
                uint32_t *slot = (uint32_t *)((char *)ef->map + addr_off);
                *slot = (uint32_t)addr;
            }
            printf("Patched kallsyms_lookup_name addr at offset 0x%zx: 0x%lx\n",
                   addr_off, addr);
            return 0;
        }
    }
    fprintf(stderr, "Note: kallsyms patch marker not found in target\n");
    return -1;
}

/* ---------- kptr_restrict (root only) ---------- */
/* 以 root 运行时，临时把 /proc/sys/kernel/kptr_restrict 置 0，
 * 让 /proc/kallsyms 暴露真实内核符号地址。非 root 则跳过。 */
static void disable_kptr_restrict_if_root(void) {
	if (geteuid() != 0) return;
	FILE *f = fopen("/proc/sys/kernel/kptr_restrict", "w");
	if (!f) {
		fprintf(stderr, "Note: cannot write /proc/sys/kernel/kptr_restrict\n");
		return;
	}
	fputs("0\n", f);
	fclose(f);
	printf("Temporarily set kptr_restrict=0\n");
}

/* ---------- Reference candidate checks ---------- */
/* 判断参考 .ko 是否同时带 init_module 和 cleanup_module 的重定位
 * （.rela.gnu.linkonce.this_module）。二者缺一不可：缺 exit 会让模块
 * 变成 [permanent]，rmmod 返回 EBUSY。 */
static int ref_has_init_exit(const ElfFile *ref_ef) {
	size_t ref_size;
	char *ref_data = (char *)elf_section_data(
	    (ElfFile *)ref_ef, ".rela.gnu.linkonce.this_module", &ref_size);
	if (!ref_data) return 0;

	int ref_init_idx = find_symbol_index((ElfFile *)ref_ef, "init_module");
	int ref_exit_idx = find_symbol_index((ElfFile *)ref_ef, "cleanup_module");
	if (ref_init_idx < 0 || ref_exit_idx < 0) return 0;

	int found_init = 0, found_exit = 0;
	if (ref_ef->is64) {
		size_t n = ref_size / sizeof(Elf64_Rela);
		Elf64_Rela *rels = (Elf64_Rela *)ref_data;
		for (size_t i = 0; i < n && !(found_init && found_exit); i++) {
			uint32_t sym = (uint32_t)(rels[i].r_info >> 32);
			if ((int)sym == ref_init_idx) found_init = 1;
			else if ((int)sym == ref_exit_idx) found_exit = 1;
		}
	} else {
		size_t n = ref_size / sizeof(Elf32_Rela);
		Elf32_Rela *rels = (Elf32_Rela *)ref_data;
		for (size_t i = 0; i < n && !(found_init && found_exit); i++) {
			uint32_t sym = rels[i].r_info >> 8;
			if ((int)sym == ref_init_idx) found_init = 1;
			else if ((int)sym == ref_exit_idx) found_exit = 1;
		}
	}
	return (found_init && found_exit);
}

/* 没给参考 .ko 时，在常见内核模块目录里找一个带 init/exit 重定位的 .ko。
 * 返回 malloc 的路径（调用方负责 free），找不到返回 NULL。 */
static char *auto_find_reference(void) {
	const char *dirs[] = {
		"/vendor/lib/modules",
		"/system/lib/modules",
		"/vendor_dlkm/lib/modules",
		"/system_dlkm/lib/modules",
		"/lib/modules",
		NULL
	};
	for (int i = 0; dirs[i]; i++) {
		DIR *d = opendir(dirs[i]);
		if (!d) continue;
		struct dirent *e;
		while ((e = readdir(d)) != NULL) {
			size_t nl = strlen(e->d_name);
			if (nl < 3 || strcmp(e->d_name + nl - 3, ".ko") != 0) continue;
			char path[1024];
			snprintf(path, sizeof(path), "%s/%s", dirs[i], e->d_name);
			ElfFile ref;
			if (elf_open(path, &ref, 0) != 0) continue;
			int ok = ref_has_init_exit(&ref);
			elf_close(&ref);
			if (ok) {
				closedir(d);
				return strdup(path);
			}
		}
		closedir(d);
	}
	return NULL;
}

/* ---------- Usage ---------- */
static void usage(const char *prog) {
	fprintf(stderr,
	        "Usage: %s <target.ko>\n"
	        "   or: %s <reference.ko> <target.ko>\n"
	        "\n"
	        "  target.ko     - The KPatcher-generated .ko file to patch in-place.\n"
	        "  reference.ko  - A .ko from the target device, used to extract vermagic,\n"
	        "                  module_layout CRC and struct module layout. Optional;\n"
	        "                  when omitted, fixup_ko searches the common module\n"
	        "                  directories and uses the first one that has both\n"
	        "                  init/exit relocations.\n",
	        prog, prog);
}

/* ---------- Main ---------- */
int main(int argc, char **argv) {
	const char *ref_path    = NULL;
	const char *target_path = NULL;
	char *auto_ref          = NULL;

	/* 参数：1 个 → target（自动搜参考）；2 个 → reference + target */
	if (argc == 2) {
		target_path = argv[1];
	} else if (argc == 3) {
		ref_path    = argv[1];
		target_path = argv[2];
	} else {
		usage(argv[0]);
		return 1;
	}

	/* 没给参考 .ko → 在常见模块路径里搜一个带 init/exit 重定位的 */
	if (!ref_path) {
		printf("No reference .ko given, searching common module paths...\n");
		auto_ref = auto_find_reference();
		if (!auto_ref) {
			fprintf(stderr, "Error: no suitable reference .ko found "
			        "(need one with init+exit relocations)\n");
			return 1;
		}
		ref_path = auto_ref;
		printf("Using reference: %s\n", ref_path);
	}

	/* 打开参考 .ko */
	ElfFile ref = {0};
	if (elf_open(ref_path, &ref, 0) != 0) {
		fprintf(stderr, "Error: cannot open reference .ko: %s\n", ref_path);
		free(auto_ref);
		return 1;
	}
	printf("Reference: %s (%d-bit ELF)\n", ref_path, ref.is64 ? 64 : 32);

	/* 参考 .ko 必须带 init/exit 重定位，否则模块会变 [permanent] */
	if (!ref_has_init_exit(&ref)) {
		fprintf(stderr, "Error: reference .ko lacks init/exit relocations: %s\n",
		        ref_path);
		elf_close(&ref);
		free(auto_ref);
		return 1;
	}

	/* vermagic 一律取自参考 */
	const char *ref_vermagic = extract_vermagic(&ref);
	if (!ref_vermagic) {
		fprintf(stderr, "Error: vermagic not found in reference .modinfo\n");
		elf_close(&ref);
		free(auto_ref);
		return 1;
	}
	char saved_vermagic[256];
	strncpy(saved_vermagic, ref_vermagic, sizeof(saved_vermagic) - 1);
	saved_vermagic[sizeof(saved_vermagic) - 1] = '\0';
	printf("Reference vermagic: %s\n", saved_vermagic);

	/* 参考 module name */
	char saved_ref_name[64] = {0};
	const char *ref_mod_name = extract_module_name(&ref);
	if (ref_mod_name) {
		strncpy(saved_ref_name, ref_mod_name, sizeof(saved_ref_name) - 1);
		printf("Reference module name: %s\n", saved_ref_name);
	}

	/* 提取 module_layout CRC */
	unsigned long ref_crc = 0;
	size_t crc_size = 0;
	if (extract_crc(&ref, "module_layout", &ref_crc, &crc_size)) {
		printf("Reference module_layout CRC: 0x%lx\n", ref_crc);
	} else {
		printf("Note: module_layout CRC not found in reference "
		       "(CONFIG_MODVERSIONS may be disabled)\n");
	}

	if (check_signature(&ref) > 0)
		printf("Note: reference .ko has a module signature (CONFIG_MODULE_SIG)\n");

	/* 打开目标 .ko（读写） */
	ElfFile target;
	if (elf_open(target_path, &target, 1) != 0) {
		fprintf(stderr, "Error: cannot open target .ko: %s\n", target_path);
		elf_close(&ref);
		free(auto_ref);
		return 1;
	}
	printf("Target: %s (%d-bit ELF)\n", target_path, target.is64 ? 64 : 32);

	if (check_signature(&target) > 0)
		printf("Note: target .ko already has a module signature\n");

	/* 修补 vermagic */
	if (patch_vermagic(&target, saved_vermagic) != 0) {
		elf_close(&ref);
		elf_close(&target);
		free(auto_ref);
		return 1;
	}

	/* 修补 module_layout CRC */
	if (crc_size > 0 && ref_crc != 0) {
		patch_crc(&target, ref_crc, crc_size);
	}

	/* 修补 .gnu.linkonce.this_module。
	 * name 不动——KPatcher 已用 -n <MODULE_NAME> 写好了正确的模块名（且与
	 * .modinfo 的 name= 一致）。参考 .ko 的名字只用于上面的日志，绝不能回写：
	 * 那是随手挑的某个 vendor 模块名，覆盖后 lsmod/rmmod 会用错名字，若该参考
	 * 模块已 insmod 还会让 loader 撞 EEXIST。 */
	patch_this_module(&target, &ref, saved_ref_name, NULL);

	/* 修正 init/exit 重定位偏移（参考已确认带这两项） */
	if (patch_rela_offsets(&target, &ref) != 0) {
		elf_close(&ref);
		elf_close(&target);
		free(auto_ref);
		return 1;
	}

	elf_close(&ref);

	/* 读 /proc/kallsyms 前，若为 root 临时关闭 kptr_restrict */
	disable_kptr_restrict_if_root();
	{
		unsigned long kaddr = read_kallsyms_lookup_name();
		if (kaddr != 0) {
			patch_kallsyms_marker(&target, kaddr);
		}
	}

	elf_close(&target);
	free(auto_ref);
	printf("Done. Patched: %s\n", target_path);
	return 0;
}
