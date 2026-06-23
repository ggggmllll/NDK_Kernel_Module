# fixup_ko

在 Android 真机上运行的 `.ko` 修补工具，配合 [KPatcher](https://github.com/ggggmllll/KPatcher) 使用：

```
loader_merged.o  ──(KPatcher, 开发机)──▶  loader.ko (模板)  ──(fixup_ko, 真机)──▶  可加载的 .ko
```

KPatcher 产出的 `.ko` 是一份**模板**：vermagic 是占位符、`module_layout` CRC 未填、`struct module` 布局没对齐目标内核。fixup_ko 拿这台真机上的一个参考 `.ko`，把内核相关的值回填进模板，让它能在这台机器上 `insmod`。

## 它修补什么

1. **vermagic**：从参考 `.ko` 的 `.modinfo` 提取 vermagic 字符串，覆盖模板里的占位符。
2. **module_layout CRC**：从参考 `.ko` 的 `__versions` 提取 `module_layout` 的 CRC，写入模板。
3. **`.gnu.linkonce.this_module`**：保留 KPatcher 写好的 2048 字节干净占位（**不**拷贝参考 `.ko` 的 `struct module`——那里面有另一台内核的陈旧指针，会让 `rmmod` 崩溃）。模块名**不改**：KPatcher 已用 `-n <MODULE_NAME>` 写好正确的名字（且与 `.modinfo` 的 `name=` 一致），fixup_ko 只读出来打印确认。绝不回写参考 `.ko` 的名字——那是随手挑的某个 vendor 模块名，覆盖后 `lsmod`/`rmmod` 会用错名字，若该参考模块已 `insmod` 还会让目标模块撞 `EEXIST`。
4. **init/exit 重定位偏移**：扫描参考 `.ko` 的 `.rela.gnu.linkonce.this_module`，取 `STT_FUNC` 类型的重定位按 offset 排序，第一个对应 `init_module`、第二个对应 `cleanup_module`，据此修正模板的重定位偏移。
5. **kallsyms 地址**：程序里埋了 32 字节魔术串，fixup_ko 在 `.ko` 里扫描它，把 `kallsyms_lookup_name` 的真实地址写进后面的 8 字节。以 root 运行时会自动把 `/proc/sys/kernel/kptr_restrict` 置 0，以便读到真实地址。

参考 `.ko` 必须同时带 `init_module` 和 `cleanup_module` 的重定位——缺 `cleanup_module` 会让模块变成 `[permanent]`，`rmmod` 返回 `EBUSY`。

## 构建

两种方式都可以：

**NDK 交叉编译**（作为 `NDK_Kernel_Module` 模板工程的子项目）：

```bash
cmake --preset android-arm64          # 在仓库根目录
cmake --build out/build/android-arm64
```

产物在 `out/build/android-arm64/fixup_ko/fixup_ko`（AArch64 PIE 可执行）。

**在 Android 设备上直接编译**（termux / 任意 C 编译器）：

```bash
cc -o fixup_ko src/fixup_ko.c -Wall
```

fixup_ko 只用标准 C 和 `<elf.h>`，无外部依赖。

## 用法

```
fixup_ko <target.ko>                    # 自动在常见模块目录搜参考 .ko
fixup_ko <reference.ko> <target.ko>     # 指定参考 .ko
```

- **target.ko**：KPatcher 生成的模板，原地修补。
- **reference.ko**：真机上的任意 `.ko`，用于提取 vermagic / CRC / `struct module` 布局。省略时，fixup_ko 依次在 `/vendor/lib/modules`、`/system/lib/modules`、`/vendor_dlkm/lib/modules`、`/system_dlkm/lib/modules`、`/lib/modules` 里找第一个**带 init+exit 重定位**的 `.ko`。

## 运行条件

- 需要 **root**：写 `/proc/sys/kernel/kptr_restrict`、读 `/proc/kallsyms`、修补内核模块文件都需要。非 root 也能跑文件修补那几步，但 kallsyms 地址读不到。
- 建议把 target.ko 和 fixup_ko 都放到可写位置（如 `/data/local/tmp`）再运行——fixup_ko 是用 `mmap(PROT_WRITE, MAP_SHARED)` 原地改 target.ko 的。
