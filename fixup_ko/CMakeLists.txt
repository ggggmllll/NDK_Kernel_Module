# fixup_ko：在 Android 真机上运行的 .ko 修补工具（ET_EXEC）
# 纯 C，依赖 <elf.h>（NDK 自带）和 POSIX API（mmap 等，Bionic 提供）。
add_executable(fixup_ko src/fixup_ko.c)
