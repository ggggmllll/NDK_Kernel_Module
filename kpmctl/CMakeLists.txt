# kpmctl — KPM loader 的用户态命令行客户端（Android arm64 PIE）
#
# 调 loader 注册的自定义 syscall（KPM_SYSCALL_NR）来 load/unload/list KPM。
# syscall 号默认 448，可在配置时用 -DKPM_SYSCALL_NR=xxx 覆盖（需与 loader
# 的 kpm_internal.h 一致），也可运行时用 `kpmctl -n <nr> ...` 覆盖。
add_executable(kpmctl src/kpmctl.c)

if(DEFINED KPM_SYSCALL_NR)
    target_compile_definitions(kpmctl PRIVATE KPM_SYSCALL_NR=${KPM_SYSCALL_NR})
endif()
