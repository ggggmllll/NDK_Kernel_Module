/*
 * kmod_kcfi.h — 给"被内核通过函数指针回调"的 loader 函数补 kCFI 类型 hash。
 *
 * 6.1 内核 CONFIG_CFI_CLANG(kCFI)：间接调用前，调用方读【目标函数 sym-4】
 * 处的 4 字节类型 hash 与期望值比对，不符则 CFI Oops。loader 把自己的回调
 * (stop_machine 的 cb、kprobe handler 等)传给内核，内核间接调它们时就会查
 * 这个 hash。loader 不是用 -fsanitize=kcfi 编的，函数前没有 hash → 崩。
 *
 * 解决：把回调放进独立 section .text.<name>，并在它正前面放一个
 * .kcfi_prefix.<name> 段，内容是 .word <hash>。module.lds 把这两段紧贴排布
 * (prefix 在前)，使 hash 落在函数入口 -4。
 *
 * 用法：
 *   KCFI_CALLBACK(hook_install_stop_cb, KCFI_HASH_INT_PTR, void *data) { ... }
 * 等价于 `static int hook_install_stop_cb(void *data) { ... }`，但带 hash 前缀。
 *
 * hash 值按【目标内核的 clang】对函数签名算出，可从 kCFI Oops 的
 * "expected type: 0x........" 直接读到。
 */
#ifndef KMOD_KCFI_H
#define KMOD_KCFI_H

/* int (*)(void *) —— stop_machine 回调、kprobe pre_handler 等常见签名。
 * 值来自 6.1.138-mi 内核 kCFI Oops: expected type 0x89fb613d。 */
#define KCFI_HASH_INT_PTR 0x89fb613d

/* 在函数前注入一个独立 section 的 4 字节 hash。section 名带 __COUNTER__ 唯一，
 * 但 module.lds 用通配 *(.kcfi_prefix.*) 统一摆到对应 .text.cb.* 前面。
 *
 * 关键约束：prefix 段和函数体段必须在 lds 里相邻且 prefix 在前。我们把回调
 * 函数显式放进 .text.kcfi_cb.<name>，prefix 放进 .kcfi_prefix.cb.<name>。 */
#define KCFI_PREFIX_SECTION(name, hash)                                   \
    __asm__(".pushsection .kcfi_prefix.cb." #name ",\"ax\",@progbits\n\t" \
            ".p2align 2\n\t"                                              \
            ".word " #hash "\n\t"                                         \
            ".popsection\n\t")

#define KCFI_CALLBACK(name, hash, ...)                                    \
    KCFI_PREFIX_SECTION(name, hash);                                      \
    __attribute__((used, section(".text.kcfi_cb." #name),                \
                   no_sanitize("cfi"), no_sanitize("kcfi")))              \
    static int name(__VA_ARGS__)

#endif /* KMOD_KCFI_H */
