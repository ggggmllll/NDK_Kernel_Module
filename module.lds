SECTIONS
{
	.text : ALIGN(4096) SUBALIGN(4) {
		*(.text)
		/* kCFI: jumptable = {.word hash, symbol: b stub}
		   Must precede .text.* so hash lands at sym - 4 */
		*(.text..L.cfi.jumptable)
		*(.text..L.cfi.jumptable.1)
		/* 自定义 syscall handler 的 kCFI prefix + 代码（必须紧贴配对，
		   使 handler-4 落在 prefix 的 hash 字段；register_syscall 偷原 hash 写入）*/
		*(.kcfi_prefix.syscall_handler)
		*(.text.syscall_handler)
		/* kCFI 回调 hash 前缀：每个 .kcfi_prefix.cb.<name> 紧贴对应
		   .text.kcfi_cb.<name> 之前，使 hash 落在函数入口 -4。
		   每加一个被内核回调的 loader 函数，就在此补一对（顺序 prefix→body）。 */
		*(.kcfi_prefix.cb.hook_install_stop_cb)
		*(.text.kcfi_cb.hook_install_stop_cb)
		*(.kcfi_prefix.cb.patch_insn_stop_cb)
		*(.text.kcfi_cb.patch_insn_stop_cb)
		*(.text.*)
	}

	.init.text  : { *(.init.text)  *(.init.text.*) }
	.exit.text  : { *(.exit.text)  *(.exit.text.*) }
	.rodata     : { *(.rodata)     *(.rodata.*) }
	.data       : { *(.data)       *(.data.*) }
	.bss        : { *(.bss)        *(.bss.*) }

	.gnu.linkonce.this_module : { *(.gnu.linkonce.this_module) }
	.modinfo   : { *(.modinfo) }
	__versions : { *(__versions) }
	__kcfi_traps : { *(__kcfi_traps) }

	.rela.text   : { *(.rela.text)   *(.rela.text.*) }
	.rela.init.text : { *(.rela.init.text) *(.rela.init.text.*) }
	.rela.exit.text : { *(.rela.exit.text) *(.rela.exit.text.*) }
	.rela.rodata : { *(.rela.rodata) *(.rela.rodata.*) }
	.rela.data   : { *(.rela.data)   *(.rela.data.*) }
	.rela.gnu.linkonce.this_module : { *(.rela.gnu.linkonce.this_module) }
	.rela__versions : { *(.rela__versions) }
	.rela__kcfi_traps : { *(.rela__kcfi_traps) }

	.symtab   : { *(.symtab) }
	.strtab   : { *(.strtab) }
	.shstrtab : { *(.shstrtab) }
	.comment  : { *(.comment) }
	.note.GNU-stack : { *(.note.GNU-stack) }
	.note     : { *(.note) *(.note.*) }
	.ARM.attributes : { *(.ARM.attributes) }
	.init.plt : { *(.init.plt) }
}
