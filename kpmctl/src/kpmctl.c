/*
 * kpmctl.c — KPM loader 的用户态命令行客户端
 *
 * loader 注册了自定义 syscall（KPM_SYSCALL_NR，默认 448）作私有通信口：
 *   syscall(NR, cmd, arg1, arg2, arg3)
 * 本工具把它包成好用的命令行，方便上机加载/卸载/列出 KPM。
 *
 * 命令（对应 loader/kpm_syscall.c）：
 *   LOAD(0)   a1=path,  a2=args   加载 KPM（args 可空）
 *   UNLOAD(1) a1=name（""=全部）  卸载
 *   LIST(2)                        列出已加载模块（详情进 dmesg）
 *   KADDR(3)  a1=hex_addr          设 kallsyms 地址（loader 里是 stub）
 *   CTL(4)    a1=name, a2=args     调 KPM 的 ctl0（结果进 dmesg）
 *   BYPASS(5)                      重新 hook CFI（幂等）
 *
 * 编译：随 NDK_Kernel_Module 的 CMake 一起出（Android arm64 PIE）。
 * 用法见 usage()。需要 root 运行（syscall 由内核模块处理）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

/* 必须与 loader/kpm_internal.h 的 KPM_SYSCALL_NR 一致。可在编译期用
 * -DKPM_SYSCALL_NR=xxx 覆盖，或运行时用 -n <nr> 覆盖。 */
#ifndef KPM_SYSCALL_NR
#define KPM_SYSCALL_NR 448
#endif

enum {
    KPM_CMD_LOAD   = 0,
    KPM_CMD_UNLOAD = 1,
    KPM_CMD_LIST   = 2,
    KPM_CMD_KADDR  = 3,
    KPM_CMD_CTL    = 4,
    KPM_CMD_BYPASS = 5,
};

static long g_nr = KPM_SYSCALL_NR;

static long kpm_call(long cmd, unsigned long a1, unsigned long a2, unsigned long a3)
{
    /* loader 的 kpm_extract_cmd 兼容两种内核：wrapper 内核 a0=pt_regs*，
     * 非 wrapper a0=cmd。用户态正常 syscall 传 cmd，内核侧自动适配。 */
    long ret = syscall(g_nr, cmd, a1, a2, a3);
    return ret;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "kpmctl — KPM loader 命令行客户端 (syscall %ld)\n"
        "\n"
        "用法: %s [-n <syscall_nr>] <命令> [参数]\n"
        "\n"
        "命令:\n"
        "  load   <path> [args]    加载 KPM 文件（args 传给模块 init，可省）\n"
        "  unload <name>           卸载指定名字的 KPM\n"
        "  unload-all              卸载全部 KPM\n"
        "  list                    列出已加载模块（详情看 dmesg）\n"
        "  ctl    <name> <args>    调用 KPM 的 ctl0（结果看 dmesg）\n"
        "  kaddr  <hex>            设置 kallsyms 地址（loader 中为 stub）\n"
        "  bypass                  重新 hook CFI（幂等）\n"
        "\n"
        "选项:\n"
        "  -n <nr>                 覆盖 syscall 号（默认 %d）\n"
        "\n"
        "示例:\n"
        "  %s load /data/local/tmp/kpm.kpm\n"
        "  %s load /data/local/tmp/kpm.kpm \"key=val\"\n"
        "  %s list\n"
        "  %s unload my_kpm\n"
        "  %s ctl my_kpm \"install 1234 0xabcd\"\n"
        "\n"
        "注意: 需 root 运行；详细输出（模块列表 / ctl 结果）打印到内核日志，\n"
        "      用 `dmesg` 查看。\n",
        g_nr, prog, KPM_SYSCALL_NR, prog, prog, prog, prog, prog);
}

static void report(const char *what, long ret)
{
    if (ret < 0) {
        /* 内核返回的是负 errno；syscall() 已把它转成 -1 + errno，
         * 但 loader 直接 return 负值时 glibc/bionic 也会照常处理。 */
        fprintf(stderr, "[kpmctl] %s 失败: ret=%ld errno=%d (%s)\n",
                what, ret, errno, strerror(errno));
    } else {
        printf("[kpmctl] %s 成功: ret=%ld\n", what, ret);
    }
}

int main(int argc, char **argv)
{
    int i = 1;

    /* 全局选项 -n <nr> */
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            g_nr = strtol(argv[i + 1], NULL, 0);
            i += 2;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "未知选项: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (i >= argc) {
        usage(argv[0]);
        return 2;
    }

    const char *cmd = argv[i++];
    long ret;

    if (strcmp(cmd, "load") == 0) {
        if (i >= argc) { fprintf(stderr, "load 需要 <path>\n"); return 2; }
        const char *path = argv[i++];
        const char *args = (i < argc) ? argv[i++] : NULL;
        ret = kpm_call(KPM_CMD_LOAD, (unsigned long)path, (unsigned long)args, 0);
        report("load", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "unload") == 0) {
        if (i >= argc) { fprintf(stderr, "unload 需要 <name>\n"); return 2; }
        const char *name = argv[i++];
        ret = kpm_call(KPM_CMD_UNLOAD, (unsigned long)name, 0, 0);
        report("unload", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "unload-all") == 0) {
        static const char empty[] = "";   /* 空名 = 全部卸载 */
        ret = kpm_call(KPM_CMD_UNLOAD, (unsigned long)empty, 0, 0);
        report("unload-all", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "list") == 0) {
        ret = kpm_call(KPM_CMD_LIST, 0, 0, 0);
        if (ret >= 0)
            printf("[kpmctl] 已加载 %ld 个模块（详情见 dmesg）\n", ret);
        else
            report("list", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "ctl") == 0) {
        if (i + 1 >= argc) { fprintf(stderr, "ctl 需要 <name> <args>\n"); return 2; }
        const char *name = argv[i++];
        const char *args = argv[i++];
        ret = kpm_call(KPM_CMD_CTL, (unsigned long)name, (unsigned long)args, 0);
        report("ctl", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "kaddr") == 0) {
        if (i >= argc) { fprintf(stderr, "kaddr 需要 <hex>\n"); return 2; }
        unsigned long addr = strtoul(argv[i++], NULL, 0);
        ret = kpm_call(KPM_CMD_KADDR, addr, 0, 0);
        report("kaddr", ret);
        return ret < 0 ? 1 : 0;
    }

    if (strcmp(cmd, "bypass") == 0) {
        ret = kpm_call(KPM_CMD_BYPASS, 0, 0, 0);
        report("bypass", ret);
        return ret < 0 ? 1 : 0;
    }

    fprintf(stderr, "未知命令: %s\n", cmd);
    usage(argv[0]);
    return 2;
}
